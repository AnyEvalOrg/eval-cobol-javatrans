"""Production task wiring/protocol only; executing gVisor requires a cluster."""
import asyncio
import base64
import hashlib
import hmac
import json
from types import SimpleNamespace

import pytest
from inspect_ai.scorer import CORRECT, INCORRECT, Target
from inspect_ai.util import ExecResult
from inspect_ai.util._sandbox.events import SandboxEnvironmentProxy

import scripts.k8s_regressions as regressions
from cobol_javatrans.sandbox_runner import (
    CLEANUP_COMMAND, QUIESCENCE_COMMAND, DIRECTORY_CLEANUP_COMMAND,
)


def test_operator_task_uses_production_sandbox():
    task = regressions.k8s_regressions()
    production = regressions.package_tasks.cobol_to_java()
    assert task.sandbox == production.sandbox
    assert task.sandbox.type == 'k8s'
    assert [s.id for s in task.dataset] == ['containment', *regressions.KERNEL_CASES]
    assert list(regressions.SAMPLE_CASES) == [s.id for s in task.dataset]
    assert all(len(regressions.SAMPLE_CASES[name]) == 1 for name in regressions.KERNEL_CASES)
    from inspect_ai.model import ModelName
    assert str(ModelName(task.model)) == 'mockllm/model'


@pytest.mark.parametrize('failure', [None, 'unsigned', 'wrong_flags', 'cleanup', 'pod'])
def test_operator_checks_all_receipts_and_pod_usability(monkeypatch, capsys, failure):
    key = bytes(range(32))
    calls = []
    cases = iter(regressions.CASES)
    current = None

    class Environment:
        async def exec(self, cmd, **kwargs):
            nonlocal current
            command = cmd
            calls.append((command, kwargs))
            output, code = '', 0
            if regressions.SETUP in command:
                current = next(cases)
                request = json.loads(kwargs['input'])
                assert request['run_argv'][-1] == regressions.CASES[current]
                output = json.dumps(dict(cwd='/tmp/cjt-fixture', key=key.hex()))
            elif regressions.RUNNER in command:
                body = dict(cwd='/tmp/cjt-fixture', stage='run',
                            returncode={'invalid_bytes': 1, 'fork_exhaustion': 1,
                                        'aggregate_memory': -9, 'disk': -9,
                                        'detached_child': 0, 'unlinked_files': -9, 'memfd_files': -9,
                                        'empty_files': -9, 'shm_write': 1, 'ptrace_denied': 1}[current],
                            timeout=False, overflow=False, cleanup_failed=False,
                            supervisor_error=False, memory_exceeded=current == 'aggregate_memory',
                            disk_exceeded=current in regressions.DISK_CASES,
                            output=base64.b64encode(b'\xff' if current == 'invalid_bytes' else
                                                  b'20\n' if current == 'fork_exhaustion' else
                                                  b'ptrace denied\n' if current == 'ptrace_denied' else b'').decode())
                if failure == 'wrong_flags':
                    body['timeout'] = True
                body = json.dumps(body)
                output = json.dumps(dict(body=body, tag=hmac.new(key, body.encode(), hashlib.sha256).hexdigest()))
                if failure == 'unsigned':
                    output = '{}'
            elif command == CLEANUP_COMMAND:
                code = 1
            elif command == DIRECTORY_CLEANUP_COMMAND and failure == 'cleanup':
                code = 137
            elif command == regressions.QUIESCENCE_CHECK_COMMAND and failure == 'pod':
                raise ConnectionError('PRIVATE_RESPONSE')
            else:
                assert command in (QUIESCENCE_COMMAND, DIRECTORY_CLEANUP_COMMAND,
                                   regressions.QUIESCENCE_CHECK_COMMAND)
            return ExecResult(success=code == 0, returncode=code, stdout=output, stderr='')

    # Avoid the deliberate absent-receipt grace period in protocol-only tests.
    cleanup = regressions.cleanup_candidate
    async def immediate_cleanup(env, not_before):
        await cleanup(env)
    monkeypatch.setattr(regressions, 'cleanup_candidate', immediate_cleanup)
    monkeypatch.setattr(regressions, 'sandbox', lambda: SandboxEnvironmentProxy(Environment()))
    state = SimpleNamespace(metadata={})
    state = asyncio.run(regressions.regressions()(state, None))
    score = asyncio.run(regressions.regression_score()(state, Target('')))
    assert score.value == (CORRECT if failure is None else INCORRECT)
    summary = json.loads(capsys.readouterr().out)
    assert summary == state.metadata['regression_flags']
    assert all(type(flag) is bool for flags in summary.values() for flag in flags.values())
    assert key.hex() not in json.dumps(summary) and 'PRIVATE_' not in json.dumps(summary)
    assert len(summary) == (1 if failure in ('cleanup', 'pod') else len(regressions.CASES))
    for command, kwargs in calls:
        assert command[:4] == ['timeout', '-s', 'KILL', '40s' if regressions.RUNNER in command else '5s']
        assert kwargs['timeout_retry'] is False


@pytest.mark.parametrize('field', ['disk_exceeded', 'memory_exceeded', 'cleanup_failed', 'supervisor_error',
                                   'overflow', 'timeout', 'output_not_decodable'])
def test_detached_success_rejects_failure_flags(field):
    receipt = dict(stage='run', returncode=0, output='', output_not_decodable=False,
                   timeout=False, overflow=False)
    receipt[field] = True
    assert not regressions.expected_receipt('detached_child', receipt)


@pytest.mark.parametrize('memory,code,output,expected', [
    (False, 1, '20\n', True), (True, -9, '', True),
    (False, 0, '20\n', False), (False, 1, '0\n', False),
])
def test_fork_receipt_accepts_gvisor_rss_limit(memory, code, output, expected):
    receipt = dict(stage='run', returncode=code, output=output,
                   output_not_decodable=False, memory_exceeded=memory)
    assert regressions.expected_receipt('fork_exhaustion', receipt) is expected


@pytest.mark.parametrize('returncode,output,supervisor_error,expected', [
    (1, 'ptrace denied\n', False, True),
    (0, '', False, False), (1, '', False, False),
    (-9, '', False, False), (1, 'ptrace denied\n', True, False),
])
def test_ptrace_denial_requires_permission_error_evidence(returncode, output, supervisor_error, expected):
    receipt = dict(stage='run', returncode=returncode, output=output,
                   supervisor_error=supervisor_error, output_not_decodable=False)
    assert regressions.expected_receipt('ptrace_denied', receipt) is expected


@pytest.mark.parametrize('outcome', ['memory', 'disk', 'oom', 'exit137', 'signal9', 'running', 'evicted', 'unsigned', 'setup_failure', 'sysv_refused', 'lookup_failure'])
def test_destructive_samples_require_resource_receipt_or_kernel_oom(monkeypatch, capsys, outcome):
    from test_sandbox_state import pod
    key = bytes(range(32))
    active = None
    setups, runs, lookups = [], [], []

    class Environment:
        async def exec(self, cmd, **kwargs):
            command = cmd
            code, output = 0, ''
            if regressions.SETUP in command:
                setups.append(active)
                if active == 'containment' or outcome == 'setup_failure':
                    code = 1
                else:
                    assert json.loads(kwargs['input'])['run_argv'][-1] == regressions.KERNEL_CASES[active]
                    output = json.dumps(dict(cwd='/tmp/cjt-fixture', key=key.hex()))
            elif regressions.RUNNER in command:
                runs.append(active)
                if outcome in ('oom', 'exit137', 'signal9', 'running', 'evicted', 'lookup_failure'):
                    raise ConnectionError('PRIVATE RESPONSE')
                from test_scoring import signed_receipt
                output = signed_receipt(key, '/tmp/cjt-fixture',
                    returncode=0 if outcome == 'sysv_refused' else -9,
                    output='sysv shm unsupported\n' if outcome == 'sysv_refused' else '',
                    memory_exceeded=outcome == 'memory', disk_exceeded=outcome == 'disk')
                if outcome == 'unsigned':
                    output = '{}'
            elif command == regressions.QUIESCENCE_CHECK_COMMAND and outcome in ('oom', 'exit137', 'signal9'):
                raise ConnectionError('PRIVATE DEAD POD')
            return ExecResult(success=code == 0, returncode=code, stdout=output, stderr='')

    async def cleanup(*args):
        if outcome in ('oom', 'exit137', 'signal9'):
            raise ConnectionError('PRIVATE DEAD POD')

    async def read(env, identity, *, evidence):
        assert identity.uid == 'sample-uid'
        evidence.update(lookup_failed=False, exception_class=None, pod_gone=False)
        lookups.append(active)
        if outcome == 'lookup_failure':
            return None
        return (pod(terminated='OOMKilled') if outcome == 'oom' else
                pod(terminated='Error', exit_code=137) if outcome == 'exit137' else
                pod(terminated='Error', signal=9) if outcome == 'signal9' else
                pod(phase='Failed', reason='Evicted', message='node pressure') if outcome == 'evicted' else pod())

    monkeypatch.setattr(regressions, 'sandbox', lambda: SandboxEnvironmentProxy(Environment()))
    monkeypatch.setattr(regressions, 'cleanup_candidate', cleanup)
    monkeypatch.setattr(regressions, 'read_sandbox_pod', read)
    monkeypatch.setattr(regressions, 'pod_identity', lambda env: SimpleNamespace(uid='sample-uid'))

    async def run():
        nonlocal active
        solve = regressions.regressions()
        for active in regressions.SAMPLE_CASES:
            state = SimpleNamespace(sample_id=active, metadata={})
            await solve(state, None)
            if active == 'containment':
                continue
            score = await regressions.regression_score()(state, Target(''))
            expected = outcome in ('memory', 'disk', 'oom', 'exit137', 'signal9') or (active == 'sysv_shm' and outcome == 'sysv_refused')
            assert score.value == (CORRECT if expected else INCORRECT)
            assert set(state.metadata['regression_flags']) == {active}
            flags = state.metadata['regression_flags'][active]
            if outcome in ('oom', 'exit137', 'signal9'):
                assert flags['oom_killed'] == (outcome == 'oom')
                assert flags['candidate_incorrect']
                assert not flags['authenticated'] and not flags['pod_usable']
    asyncio.run(run())
    assert setups == list(regressions.SAMPLE_CASES)
    assert runs == ([] if outcome == 'setup_failure' else list(regressions.KERNEL_CASES))
    assert lookups == (list(regressions.KERNEL_CASES) if outcome in ('oom', 'exit137', 'signal9', 'running', 'evicted', 'unsigned', 'lookup_failure') else [])
    output = capsys.readouterr().out
    assert 'PRIVATE' not in output and key.hex() not in output
    for line in output.splitlines():
        assert all(type(flag) is bool for flags in json.loads(line).values() for flag in flags.values())


def test_concurrent_samples_cannot_start_kernel_candidates_before_containment(monkeypatch, capsys):
    from contextvars import ContextVar
    active = ContextVar('regression_sample')
    starts = []

    class Environment:
        async def exec(self, cmd, **kwargs):
            if regressions.SETUP in cmd:
                starts.append(active.get())
                # End each sample at setup; ordering doesn't need a real runner.
                return ExecResult(success=False, returncode=1, stdout='', stderr='')
            return ExecResult(success=True, returncode=0, stdout='', stderr='')

    async def cleanup(*args):
        pass
    monkeypatch.setattr(regressions, 'sandbox', lambda: SandboxEnvironmentProxy(Environment()))
    monkeypatch.setattr(regressions, 'cleanup_candidate', cleanup)

    async def run():
        solve = regressions.regressions()
        async def sample(name):
            active.set(name)
            await solve(SimpleNamespace(sample_id=name, metadata={}), None)
        # All later samples reach their barrier before containment starts.
        async with asyncio.timeout(1):
            await asyncio.gather(*(sample(name) for name in reversed(regressions.SAMPLE_CASES)))
    asyncio.run(run())
    assert starts == list(regressions.SAMPLE_CASES)
    capsys.readouterr()


@pytest.mark.parametrize('outcome', ['found', 'gone', 'error', 'unsigned'])
def test_missing_receipt_metadata_records_same_lookup_evidence(monkeypatch, capsys, outcome):
    from cobol_javatrans import sandbox_state as ss
    from test_sandbox_state import pod
    from kubernetes.client.exceptions import ApiException
    key = bytes(range(32))
    identity = SimpleNamespace(uid='sample-uid')
    observed = pod(phase='Failed', reason='Error', message='KUBELET ' * 50,
                   terminated='Error', exit_code=137, signal=9,
                   last='Error', last_exit_code=1, last_signal=15)
    observed.status.container_statuses[0].state.terminated.message = 'CURRENT ' * 50
    observed.status.container_statuses[0].last_state.terminated.message = 'PREVIOUS ' * 50
    observed.status.container_statuses.append(pod().status.container_statuses[0])
    calls = []

    class Environment:
        async def exec(self, cmd, **kwargs):
            if regressions.SETUP in cmd:
                return ExecResult(success=True, returncode=0,
                    stdout=json.dumps(dict(cwd='/tmp/cjt-fixture', key=key.hex())), stderr='')
            if regressions.RUNNER in cmd:
                if outcome == 'unsigned':
                    return ExecResult(success=False, returncode=137, stdout='PRIVATE OUTPUT', stderr='PRIVATE')
                raise ConnectionError('PRIVATE RUNNER ERROR')
            raise ConnectionError('PRIVATE DEAD POD')

    async def cleanup(*args):
        await asyncio.sleep(0.01)
        raise ConnectionError('PRIVATE CLEANUP')

    def read(captured):
        assert captured is identity
        calls.append(captured)
        if outcome == 'gone':
            raise ApiException(status=404, reason='PRIVATE API BODY')
        if outcome == 'error':
            raise RuntimeError('PRIVATE LOOKUP ERROR')
        return observed

    def classify(actual, captured):
        assert actual is (observed if outcome in ('found', 'unsigned') else None)
        assert captured is identity
        return ss.classify_pod(actual, captured)

    monkeypatch.setattr(regressions, 'SAMPLE_CASES', {'sysv_shm': {'sysv_shm': regressions.KERNEL_CASES['sysv_shm']}})
    monkeypatch.setattr(regressions, 'sandbox', lambda: SandboxEnvironmentProxy(Environment()))
    monkeypatch.setattr(regressions, 'pod_identity', lambda env: identity)
    monkeypatch.setattr(regressions, 'cleanup_candidate', cleanup)
    monkeypatch.setattr(regressions, 'classify_pod', classify)
    monkeypatch.setattr(ss, '_read_pod', read)
    state = SimpleNamespace(sample_id='sysv_shm', metadata={})
    asyncio.run(regressions.regressions()(state, None))
    evidence = state.metadata['regression_evidence']['sysv_shm']
    assert calls == [identity]
    assert evidence['runner_exec_to_lookup_seconds'] >= 0.01
    assert evidence['lookup_failed'] == (outcome in ('gone', 'error'))
    assert evidence['exception_class'] == {'gone': 'ApiException', 'error': 'RuntimeError'}.get(outcome)
    assert evidence['pod_gone'] == (outcome == 'gone')
    if outcome in ('found', 'unsigned'):
        assert evidence['pod'] == dict(phase='Failed', reason='Error', message=('KUBELET ' * 50)[:200],
            containerStatuses=[dict(
                state=dict(terminated=dict(reason='Error', exitCode=137, signal=9, message=('CURRENT ' * 50)[:200])),
                lastState=dict(terminated=dict(reason='Error', exitCode=1, signal=15, message=('PREVIOUS ' * 50)[:200]))),
                dict(state=dict(terminated=None), lastState=dict(terminated=None))])
    else:
        assert evidence['pod'] == dict(phase=None, reason=None, message=None, containerStatuses=[])
    assert 'PRIVATE' not in json.dumps(state.metadata)
    output = capsys.readouterr().out
    assert 'KUBELET' not in output and 'PRIVATE' not in output and key.hex() not in output
