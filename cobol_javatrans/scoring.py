"""All-tests pass@1; only the external sandbox runs candidate programs."""
from __future__ import annotations

import ast
import asyncio
import json
import io
import re

from inspect_ai.scorer import CORRECT, INCORRECT, Score, Target, accuracy, scorer
from inspect_ai.solver import TaskState
from inspect_ai.util import sandbox

from .receipt import verify_receipt, receipt_failure
from .dataset import load_records
from .publication import private_grading
from .sandbox_runner import CLEANUP_COMMAND, QUIESCENCE_COMMAND, DIRECTORY_CLEANUP_COMMAND, RUNNER, SETUP
from .execution import execution_request
from .sandbox_state import pod_identity, sandbox_failure
from .cleaning import clean_java_response, clean_response_for_eval
from .comparison import parse, is_equal

def extract_code(completion: str, language: str) -> str | None:
    blocks = re.findall(r"^```" + language + r"[^\S\n]*\r?\n(.*?)^```[^\S\n]*\r?$", completion, re.M | re.S)
    if len(blocks) != 1 or not blocks[0].strip():
        return None
    return (clean_java_response if language == 'java' else clean_response_for_eval)(blocks[0])


def cobol_matches(output: str, result: dict) -> bool:
    # All 807 frozen expected values are literals. Never use upstream's eval().
    expected = ast.literal_eval(result['value'])
    if isinstance(expected, tuple):
        expected = list(expected)
    try:
        lines = io.StringIO(output, newline=None).readlines()
        return bool(lines) and is_equal(result['type_'], parse(lines, result['type_'], expected), expected)
    except Exception:
        return False


@scorer(metrics=[accuracy()])
def translation_scorer(direction: str):
    """A timeout, runtime error, missing code, or any wrong answer fails a problem."""
    if direction not in {"cobol_to_java", "java_to_cobol"}:
        raise ValueError("Invalid translation direction")
    language = "java" if direction == "cobol_to_java" else "cobol"

    # Closure data is not a scorer argument (Inspect logs scorer arguments), sample
    # metadata, target, or store. Only the selected record is decoded when scoring.
    records = {record["task_id"]: record for record in load_records()}

    async def private_score(state: TaskState, target: Target) -> Score:
        code = extract_code(state.output.completion, language)
        if code is None:
            return Score(value=INCORRECT, explanation=f"Expected one nonempty, closed {language} fenced block.")
        record = records[str(state.sample_id)]
        tests = [None] if direction == 'cobol_to_java' else record['tests']
        if not tests:
            raise ValueError('Packaged problem has no tests')
        env = sandbox()
        for index, test in enumerate(tests, 1):
            payload = execution_request(code, record, direction, test)
            request = json.dumps(payload)
            # Compile and run are independently timed, credential-dropped steps
            # inside one root supervisor; no candidate-controlled driver verdict.
            deadline = payload['timeout'] + payload['run_timeout'] + 10
            receipt = None
            kernel_score = None
            setup_succeeded = False
            failure = None
            cleanup_failed = False
            cleanup_after = 0
            try:
                with private_grading(env) as private:
                    try:
                        async with asyncio.timeout(10):
                            setup = await private.exec(
                                ["timeout", "-s", "KILL", "5s",
                                 "/usr/local/bin/python3", "-I", "-c", SETUP],
                                cwd="/", input=request, timeout=5, timeout_retry=False,
                            )
                        if setup.returncode != 0:
                            raise RuntimeError("Sandbox setup failed")
                        setup_receipt = json.loads(setup.stdout)
                        work = setup_receipt["cwd"]
                        key = bytes.fromhex(setup_receipt["key"])
                        if len(key) != 32:
                            raise RuntimeError("Invalid setup key")
                        if not re.fullmatch(r"/tmp/cjt-[a-zA-Z0-9_-]+", work):
                            raise RuntimeError("Invalid setup directory")
                        setup_succeeded = True
                        identity = pod_identity(private)
                        # If exec returns early without a receipt, wait through
                        # the outer deadline before sweeping: the supervisor may
                        # still be starting. This uses the host monotonic clock.
                        cleanup_after = asyncio.get_running_loop().time() + deadline + 5
                        try:
                            async with asyncio.timeout(deadline + 5):
                                result = await private.exec(
                                    ["timeout", "-s", "KILL", f"{deadline}s",
                                     "/usr/local/bin/python3", "-I", "-c", RUNNER, work],
                                    cwd="/", timeout=deadline, timeout_retry=False,
                                )
                            receipt = verify_receipt(result.stdout, key)
                            if receipt is not None and receipt["cwd"] == work:
                                # Authenticated completion means no later spawn;
                                # sweep immediately before starting the next test.
                                cleanup_after = 0
                                # Decide from authenticated evidence BEFORE cleanup.
                                failure = receipt_failure(receipt)
                                if (failure is None and direction == 'java_to_cobol'
                                        and not cobol_matches(receipt['output'], test['result'])):
                                    failure = "wrong answer."
                            else:
                                receipt = None
                        except Exception:
                            # Kubernetes is the only remaining verdict channel.
                            receipt = None
                    finally:
                        # A separate sandbox exec, never the candidate's parent or
                        # session, enforces cleanup on EVERY path (also setup failure).
                        cleanup = asyncio.create_task(cleanup_candidate(private, cleanup_after))
                        try:
                            await asyncio.shield(cleanup)
                        except asyncio.CancelledError:
                            await cleanup
                            raise
                        except Exception:
                            # Pods are per-sample and discarded afterwards: never
                            # reuse after failed cleanup, but retain signed failure.
                            cleanup_failed = True
                    if setup_succeeded and receipt is None:
                        kernel_score = await sandbox_failure(private, identity)
            except Exception:
                # Provider exceptions may embed stdin or captured output. Do not
                # allow them (or their exception chain) into an Inspect error event.
                raise RuntimeError("Private sandbox operation failed; details withheld.") from None
            # Neither success nor returncode from the run provider is a verdict channel.
            if receipt is None:
                if kernel_score is not None:
                    return Score(value=kernel_score.value,
                                 explanation=f"Test {index}: {kernel_score.explanation}")
                # A Running pod plus exit 137/timeout is NOT proof that the
                # candidate exceeded a supervisor deadline: the exec transport,
                # node scheduling, or supervisor can fail identically. Calling
                # it INCORRECT would admit infrastructure failures into the rate.
                # Keep a withheld sample error (including timeout -s KILL).
                # Publication must reject runs with ANY sample errors, as AnyEval
                # does, rather than drop errored samples and publish a partial
                # rate. Signed candidate timeouts and kernel OOMs remain verdicts.
                raise RuntimeError("Private sandbox operation failed; details withheld.") from None
            if failure is not None:
                return Score(value=INCORRECT, explanation=f"Test {index}: {failure}")
            if cleanup_failed:
                return Score(value=INCORRECT, explanation=
                             "candidate left processes that could not be cleaned up")
        return Score(value=CORRECT, explanation=f"All {len(tests)} tests passed.")

    async def score(state: TaskState, target: Target) -> Score:
        # Raise outside the private frame and except block: even Inspect's optional
        # traceback-locals display must not render records, requests, keys or output.
        try:
            return await private_score(state, target)
        except Exception:
            pass
        raise RuntimeError("Private sandbox operation failed; details withheld.") from None

    return score


async def cleanup_candidate(environment, not_before: float = 0) -> None:
    """Bounded independent UID sweep and deletion; caller applies receipt verdict."""
    try:
        delay = not_before - asyncio.get_running_loop().time()
        if delay > 0:
            await asyncio.sleep(delay)
        async with asyncio.timeout(10):
            cleanup = await environment.exec(
                list(CLEANUP_COMMAND), cwd="/", timeout=5, timeout_retry=False,
            )
        if cleanup.returncode not in (0, 1):
            raise RuntimeError("UID cleanup failed")
        async with asyncio.timeout(10):
            checked = await environment.exec(
                list(QUIESCENCE_COMMAND), cwd="/", timeout=5, timeout_retry=False,
            )
        if checked.returncode != 0:
            raise RuntimeError("UID cleanup did not reach quiescence")
        async with asyncio.timeout(10):
            deleted = await environment.exec(
                list(DIRECTORY_CLEANUP_COMMAND), cwd="/", timeout=5, timeout_retry=False,
            )
        if deleted.returncode != 0:
            raise RuntimeError("Directory cleanup failed")
    except Exception:
        # The caller preserves signed failures and penalizes signed successes.
        raise RuntimeError("Private sandbox cleanup failed; details withheld.") from None
