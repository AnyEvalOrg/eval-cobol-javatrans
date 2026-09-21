"""Operator-only production gVisor regressions; intentionally not a registry task."""
import asyncio
import json
from pathlib import Path
import sys

from inspect_ai import Task, task
from inspect_ai.dataset import Sample
from inspect_ai.scorer import CORRECT, INCORRECT, Score, accuracy, scorer
from inspect_ai.solver import solver
from inspect_ai.util import sandbox

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cobol_javatrans.task as package_tasks
from cobol_javatrans.publication import private_grading
from cobol_javatrans.receipt import verify_receipt, receipt_failure
from cobol_javatrans.sandbox_runner import SETUP, RUNNER, QUIESCENCE_CHECK_COMMAND
from cobol_javatrans.scoring import cleanup_candidate
from scripts.linux_regressions import (
    INVALID_BYTES, FORK_EXHAUSTION, AGGREGATE_MEMORY,
    DETACHED_CHILD, DISK_CASES, SHM_WRITE, PTRACE_DENIED, FLAGS, PYTHON, request_for,
)

CASES = {
    'invalid_bytes': INVALID_BYTES,
    'fork_exhaustion': FORK_EXHAUSTION,
    'aggregate_memory': AGGREGATE_MEMORY,
    **DISK_CASES,
    'shm_write': SHM_WRITE,
    'ptrace_denied': PTRACE_DENIED,
    'detached_child': DETACHED_CHILD,
}


def expected_receipt(name, receipt):
    if receipt['stage'] != 'run':
        return False
    if any(receipt.get(k) for k in ('timeout', 'overflow', 'cleanup_failed', 'supervisor_error')):
        return False
    if name != 'fork_exhaustion' and bool(receipt.get('memory_exceeded')) != (name == 'aggregate_memory'):
        return False
    if bool(receipt.get('disk_exceeded')) != (name in DISK_CASES):
        return False
    if bool(receipt['output_not_decodable']) != (name == 'invalid_bytes'):
        return False
    if name == 'invalid_bytes':
        return receipt['output_not_decodable'] and receipt['returncode'] != 0
    if name == 'fork_exhaustion':
        # gVisor charges copy-on-write RSS once per fork; either limit is valid.
        return bool(receipt.get('memory_exceeded')) or (
            receipt['returncode'] == 1 and 0 < int(receipt['output'].strip()) < 64)
    if name == 'aggregate_memory':
        return receipt.get('memory_exceeded', False) and receipt['returncode'] != 0
    if name in DISK_CASES:
        return receipt.get('disk_exceeded', False) and receipt['returncode'] != 0
    if name == 'ptrace_denied':
        return receipt['returncode'] == 1 and receipt['output'] == 'ptrace denied\n'
    if name == 'shm_write':
        return receipt['returncode'] == 1
    return receipt_failure(receipt) is None


@solver
def regressions():
    async def solve(state, generate):
        summary = {}
        # Use the real sandbox().exec path while suppressing keys/receipts in
        # Inspect events. Persist and print only boolean flags, never raw output.
        with private_grading(sandbox()) as env:
            for name, code in CASES.items():
                flags = dict(authenticated=False, expected=False,
                             cleanup_ok=False, pod_usable=False, receipt_within_deadline=False)
                cleanup_after = 0
                try:
                    async with asyncio.timeout(10):
                        setup_result = await env.exec(
                            ['timeout', '-s', 'KILL', '5s', PYTHON, '-I', '-c', SETUP],
                            input=json.dumps(request_for(code)), cwd='/', timeout=5, timeout_retry=False)
                    setup = json.loads(setup_result.stdout)
                    started = asyncio.get_running_loop().time()
                    cleanup_after = started + 45
                    async with asyncio.timeout(45):
                        result = await env.exec(
                            ['timeout', '-s', 'KILL', '40s', PYTHON, '-I', '-c', RUNNER, setup['cwd']],
                            cwd='/', timeout=40, timeout_retry=False)
                    receipt = verify_receipt(result.stdout, bytes.fromhex(setup['key']))
                    if receipt is not None and receipt['cwd'] == setup['cwd']:
                        cleanup_after = 0
                        flags['authenticated'] = True
                        flags['receipt_within_deadline'] = asyncio.get_running_loop().time() - started < 40
                        flags.update({k: bool(receipt.get(k, False)) for k in FLAGS})
                        flags['expected'] = bool(expected_receipt(name, receipt))
                except Exception:
                    pass
                finally:
                    try:
                        await cleanup_candidate(env, cleanup_after)
                        flags['cleanup_ok'] = True
                    except Exception:
                        pass
                try:
                    async with asyncio.timeout(10):
                        probe = await env.exec(list(QUIESCENCE_CHECK_COMMAND), cwd='/',
                                               timeout=5, timeout_retry=False)
                    flags['pod_usable'] = probe.returncode == 0
                except Exception:
                    pass
                summary[name] = flags
                if not flags['cleanup_ok'] or not flags['pod_usable']:
                    break  # Never start another candidate after failed cleanup.
        state.metadata['regression_flags'] = summary
        print(json.dumps(summary), flush=True)
        return state
    return solve


@scorer(metrics=[accuracy()])
def regression_score():
    async def score(state, target):
        summary = state.metadata.get('regression_flags', {})
        passed = set(summary) == set(CASES) and all(
            all(flags.get(k, False) for k in ('authenticated', 'expected', 'cleanup_ok', 'pod_usable', 'receipt_within_deadline'))
            for flags in summary.values())
        return Score(value=CORRECT if passed else INCORRECT)
    return score


@task
def k8s_regressions():
    return Task(dataset=[Sample(id='containment', input='Run synthetic containment regressions.')],
                solver=regressions(), scorer=regression_score(), model='mockllm/model',
                sandbox=package_tasks.cobol_to_java().sandbox)
