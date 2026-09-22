"""Operator-only production gVisor regressions; intentionally not a registry task."""
import asyncio
import json
from pathlib import Path
import re
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
from cobol_javatrans.sandbox_state import pod_identity, read_sandbox_pod, classify_pod, MEMORY_FAILURE
from scripts.linux_regressions import (
    INVALID_BYTES, FORK_EXHAUSTION, AGGREGATE_MEMORY,
    DETACHED_CHILD, DISK_CASES, SHM_WRITE, PTRACE_DENIED, FLAGS, PYTHON, request_for,
    KERNEL_CASES, kernel_receipt, sysv_unsupported,
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
SAMPLE_CASES = {'containment': CASES, **{name: {name: code} for name, code in KERNEL_CASES.items()}}


def pod_evidence(pod):
    """Allowlisted kubelet evidence from the exact object passed to the classifier."""
    def message(value):
        return value[:200] if value is not None else None

    def termination(state):
        terminated = getattr(state, 'terminated', None)
        if terminated is None:
            return None
        return dict(reason=getattr(terminated, 'reason', None),
                    exitCode=getattr(terminated, 'exit_code', None),
                    signal=getattr(terminated, 'signal', None),
                    message=message(getattr(terminated, 'message', None)))

    status = getattr(pod, 'status', None)
    return dict(phase=getattr(status, 'phase', None),
                reason=getattr(status, 'reason', None),
                message=message(getattr(status, 'message', None)),
                containerStatuses=[dict(
                    state=dict(terminated=termination(c.state)),
                    lastState=dict(terminated=termination(c.last_state)))
                    for c in (getattr(status, 'container_statuses', None) or [])])


def expected_receipt(name, receipt):
    if name in KERNEL_CASES:
        return kernel_receipt(name, receipt)
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
    # Inspect can schedule samples concurrently. Keep the destructive cases last
    # even then, with one fresh pod per Sample and no reuse after a kernel hog.
    finished = {name: asyncio.Event() for name in SAMPLE_CASES}
    order = list(SAMPLE_CASES)
    async def solve(state, generate):
        sample = str(getattr(state, 'sample_id', 'containment'))
        position = order.index(sample)
        if position:
            await finished[order[position - 1]].wait()
        summary = {}
        evidence = {}
        # Use the real sandbox().exec path while suppressing keys/receipts in
        # Inspect events. Print only boolean flags, never raw output. Allowlisted
        # Kubernetes evidence is persisted separately in operator sample metadata.
        with private_grading(sandbox()) as env:
            for name, code in SAMPLE_CASES[sample].items():
                flags = dict(authenticated=False, expected=False,
                             cleanup_ok=False, pod_usable=False, receipt_within_deadline=False)
                cleanup_after = 0
                setup_succeeded = False
                identity = None
                runner_finished = None
                try:
                    async with asyncio.timeout(10):
                        setup_result = await env.exec(
                            ['timeout', '-s', 'KILL', '5s', PYTHON, '-I', '-c', SETUP],
                            input=json.dumps(request_for(code)), cwd='/', timeout=5, timeout_retry=False)
                    if setup_result.returncode != 0:
                        raise RuntimeError('setup failed')
                    setup = json.loads(setup_result.stdout)
                    key = bytes.fromhex(setup['key'])
                    if len(key) != 32 or not re.fullmatch(r'/tmp/cjt-[a-zA-Z0-9_-]+', setup['cwd']):
                        raise RuntimeError('setup failed')
                    setup_succeeded = True
                    identity = pod_identity(env)
                    started = asyncio.get_running_loop().time()
                    cleanup_after = started + 45
                    try:
                        async with asyncio.timeout(45):
                            result = await env.exec(
                                ['timeout', '-s', 'KILL', '40s', PYTHON, '-I', '-c', RUNNER, setup['cwd']],
                                cwd='/', timeout=40, timeout_retry=False)
                    finally:
                        # Includes exceptions/timeouts; for an unsigned response,
                        # measure from exec returning instead. Excludes setup.
                        runner_finished = asyncio.get_running_loop().time()
                    receipt = verify_receipt(result.stdout, key)
                    if receipt is not None and receipt['cwd'] == setup['cwd']:
                        cleanup_after = 0
                        flags['authenticated'] = True
                        flags['receipt_within_deadline'] = asyncio.get_running_loop().time() - started < 40
                        flags.update({k: bool(receipt.get(k, False)) for k in FLAGS})
                        flags['expected'] = bool(expected_receipt(name, receipt))
                        if name in KERNEL_CASES:
                            flags['sysv_unsupported'] = sysv_unsupported(name, receipt)
                except Exception:
                    pass
                finally:
                    try:
                        await cleanup_candidate(env, cleanup_after)
                        flags['cleanup_ok'] = True
                    except Exception:
                        pass
                if setup_succeeded and not flags['authenticated']:
                    lookup = dict(runner_exec_to_lookup_seconds=(
                        asyncio.get_running_loop().time() - runner_finished
                        if runner_finished is not None else None))
                    pod = await read_sandbox_pod(env, identity, evidence=lookup)
                    evidence[name] = dict(**lookup, pod=pod_evidence(pod))
                if name in KERNEL_CASES and setup_succeeded and not flags['authenticated']:
                    classified = classify_pod(pod, identity)
                    status = getattr(pod, 'status', None)
                    flags['oom_killed'] = any(
                        getattr(getattr(s, 'terminated', None), 'reason', None) == 'OOMKilled'
                        for c in (getattr(status, 'container_statuses', None) or [])
                        for s in (c.state, c.last_state))
                    flags['candidate_incorrect'] = bool(classified is not None
                        and classified.value == INCORRECT and classified.explanation == MEMORY_FAILURE)
                    flags['expected'] = flags['candidate_incorrect']
                try:
                    async with asyncio.timeout(10):
                        probe = await env.exec(list(QUIESCENCE_CHECK_COMMAND), cwd='/',
                                               timeout=5, timeout_retry=False)
                    flags['pod_usable'] = probe.returncode == 0
                except Exception:
                    pass
                summary[name] = flags
                if not setup_succeeded or not flags['cleanup_ok'] or not flags['pod_usable']:
                    break  # Never start another candidate after failed cleanup.
        state.metadata['regression_flags'] = summary
        state.metadata['regression_evidence'] = evidence
        print(json.dumps(summary), flush=True)
        finished[sample].set()
        return state
    return solve


@scorer(metrics=[accuracy()])
def regression_score():
    async def score(state, target):
        summary = state.metadata.get('regression_flags', {})
        sample = str(getattr(state, 'sample_id', 'containment'))
        passed = set(summary) == set(SAMPLE_CASES[sample]) and all(
            all(flags.get(k, False) for k in ('authenticated', 'expected', 'cleanup_ok', 'pod_usable', 'receipt_within_deadline'))
            or (name in KERNEL_CASES and not flags.get('authenticated') and all(
                flags.get(k, False) for k in ('expected', 'candidate_incorrect')))
            for name, flags in summary.items())
        return Score(value=CORRECT if passed else INCORRECT)
    return score


@task
def k8s_regressions():
    return Task(dataset=[Sample(id=name, input='Run synthetic containment regressions.')
                         for name in SAMPLE_CASES],
                solver=regressions(), scorer=regression_score(), model='mockllm/model',
                sandbox=package_tasks.cobol_to_java().sandbox)
