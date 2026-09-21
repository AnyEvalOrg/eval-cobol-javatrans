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
    assert len(task.dataset) == 1
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
