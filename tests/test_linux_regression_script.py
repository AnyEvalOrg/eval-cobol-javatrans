"""Protocol/wiring tests only; the standalone script supplies real Linux checks."""
import base64
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest


@pytest.fixture
def regressions(monkeypatch):
    # Load the operator script without importing Inspect in the reference image.
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / 'cobol_javatrans'))
    spec = importlib.util.spec_from_file_location('linux_regressions', Path(__file__).resolve().parents[1] / 'scripts/linux_regressions.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize('budget', [False, True])
def test_script_uses_actual_setup_runner_and_authenticated_failure(monkeypatch, regressions, budget, capsys):
    key = bytes(range(32))
    calls = []

    def invoke(command, **kwargs):
        calls.append(command)
        if regressions.SETUP in command:
            assert json.loads(kwargs['input'])['run_argv'][-1] == regressions.INVALID_BYTES
            stdout = json.dumps(dict(cwd='/tmp/cjt-regression', key=key.hex()))
        elif regressions.RUNNER in command:
            assert ('prlimit' in command) is budget
            if budget:
                assert '--as=536870912:536870912' in command
                assert '--data=536870912:536870912' in command
            body = json.dumps(dict(cwd='/tmp/cjt-regression', stage='run', returncode=1,
                                   timeout=False, overflow=False, output=base64.b64encode(b'\xff').decode()))
            stdout = json.dumps(dict(body=body, tag=hmac.new(key, body.encode(), hashlib.sha256).hexdigest()))
        else:
            return SimpleNamespace(returncode=1 if command == regressions.CLEANUP_COMMAND else 0, stdout='')
        return SimpleNamespace(returncode=0, stdout=stdout)

    monkeypatch.setattr(regressions, 'invoke', invoke)
    monkeypatch.setattr(regressions.shutil, 'rmtree', lambda *args, **kwargs: None)
    regressions.check_failure(regressions.INVALID_BYTES, budget=budget)
    assert calls[0] == regressions.QUIESCENCE_CHECK_COMMAND
    assert calls[-4:] == [regressions.CLEANUP_COMMAND, regressions.QUIESCENCE_COMMAND,
                          regressions.DIRECTORY_CLEANUP_COMMAND, regressions.QUIESCENCE_CHECK_COMMAND]
    summary = json.loads(capsys.readouterr().out)
    assert set(summary) == {'stage', 'returncode', 'flags'}
    assert summary['flags']['incorrect'] and summary['flags']['output_not_decodable']


@pytest.mark.parametrize('error,label', [
    (AssertionError('quiescent-before-setup'), 'quiescent-before-setup'),
    (AssertionError('candidate-secret'), None),
    (AssertionError(b'candidate-secret'), None),
    (ValueError('candidate-secret'), None),
    (subprocess.TimeoutExpired(['candidate-secret'], 50, output=b'candidate-secret'), None),
    (UnicodeDecodeError('utf-8', b'candidate-secret\xff', 16, 17, 'secret'), None),
])
def test_failure_report_never_prints_exception_text(regressions, capsys, error, label):
    with pytest.raises(SystemExit) as stopped:
        with regressions.check('startup'):
            with regressions.check('compiler_smoke:cobc'):
                raise error
    assert stopped.value.code == 1
    captured = capsys.readouterr()
    summary = json.loads(captured.out)  # Exactly one JSON report, even when nested.
    assert summary == dict(stage='regression', step='compiler_smoke:cobc',
                           error=type(error).__name__, returncode=1,
                           flags={'regression_failed': True},
                           **({'label': label} if label else {}))
    assert captured.err == ''
    assert 'candidate-secret' not in captured.out


def passing_receipt():
    return dict(stage='run', returncode=0, timeout=False, overflow=False,
                output_not_decodable=False, output='candidate-secret')


@pytest.mark.parametrize('failure,label', [
    ({'stage': 'compile'}, 'compile-completed'),
    ({'returncode': 1}, 'compiler-success'),
    ({'cleanup_failed': True}, 'compiler-success'),
])
def test_second_compiler_failure_is_named(monkeypatch, regressions, capsys, failure, label):
    requests = []

    def execute(request):
        requests.append(request)
        receipt = passing_receipt()
        if request['argv'][0] == 'cobc':
            receipt.update(failure)
        return receipt

    monkeypatch.setattr(regressions, 'execute', execute)
    with pytest.raises(SystemExit):
        regressions.compiler_smokes()
    first, second = map(json.loads, capsys.readouterr().out.splitlines())
    assert first['flags']['compiler_startup'] is True
    assert second['step'] == 'compiler_smoke:cobc'
    assert second['error'] == 'AssertionError'
    assert second['label'] == label
    assert [r['argv'][0] for r in requests] == ['javac', 'cobc']
    assert all('run_argv' in r for r in requests)
    assert 'candidate-secret' not in json.dumps([first, second])


def test_preflight_failure_has_label_and_never_starts_setup(monkeypatch, regressions, capsys):
    calls = []

    def invoke(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=2)

    monkeypatch.setattr(regressions, 'invoke', invoke)
    with pytest.raises(SystemExit):
        with regressions.check('compiler_smoke:cobc'):
            regressions.execute({})
    summary = json.loads(capsys.readouterr().out)
    assert summary['label'] == 'quiescent-before-setup'
    assert calls == [regressions.QUIESCENCE_CHECK_COMMAND]


@pytest.mark.parametrize('kill_status,quiescence_status,label', [
    (2, 0, 'cleanup-kill'), (0, 1, 'cleanup-quiescent'),
    (0, 2, 'cleanup-quiescent'), (1, 0, None), (0, 0, None),
])
def test_cleanup_returncodes(monkeypatch, regressions, kill_status, quiescence_status, label):
    def invoke(command):
        return SimpleNamespace(returncode=(kill_status if command == regressions.CLEANUP_COMMAND else
                                         quiescence_status if command == regressions.QUIESCENCE_COMMAND else 0))

    monkeypatch.setattr(regressions, 'invoke', invoke)
    if label:
        with pytest.raises(AssertionError) as failure:
            regressions.independent_cleanup()
        assert failure.value.args == (label,)
    else:
        regressions.independent_cleanup()


def test_cloudbuild_provides_reference_image_and_nested_docker_socket():
    import yaml
    config = yaml.safe_load((Path(__file__).resolve().parents[1] / 'scripts/cloudbuild-linux-regressions.yaml').read_text())
    step, = config['steps']
    assert step['name'] == 'gcr.io/cloud-builders/docker'
    command = step['args'][-1]
    assert '/var/run/docker.sock:/var/run/docker.sock' in command
    assert 'cp "$$(command -v docker)" /workspace/.linux-regressions/docker' in command
    assert '--docker-cli /workspace/.linux-regressions/docker' in command
    assert '--read-only --volume /tmp --tmpfs /dev/shm:ro,size=16m' in command
    assert '--cap-add=SYS_PTRACE' in command
    assert '--image' in command and '${_IMAGE}' in command
    assert '/workspace/scripts/linux_regressions.py' in command


def test_docker_uses_aggregate_memory_and_disk_budgets(monkeypatch, regressions, capsys):
    calls = []
    summaries = [
        dict(stage='run', returncode=-9, flags=dict(incorrect=True, memory_exceeded=True)),
        *[dict(stage='run', returncode=-9, flags=dict(incorrect=True, disk_exceeded=True))
          for _ in regressions.DISK_CASES],
        dict(stage='run', returncode=1, flags=dict(incorrect=True)),
        dict(stage='run', returncode=1, flags=dict(incorrect=True)),
    ]
    def invoke(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout='\n'.join(map(json.dumps, summaries)))
    monkeypatch.setattr(regressions, 'invoke', invoke)
    regressions.docker_memory_check('docker-fixture', 'reference-image')
    command = calls[1]
    for option in ('--memory=2g', '--memory-swap=2g', '--read-only', '--cap-add=SYS_PTRACE', '/dev/shm:ro,size=16m'):
        assert option in command
    assert command[command.index('--tmpfs') + 1] == '/dev/shm:ro,size=16m'
    assert command[command.index('--volume') + 1] == '/tmp'
    assert command[-1] == '--memory-child'
    assert calls[-1][:3] == ['docker-fixture', 'rm', '-f']
    assert '-v' in calls[-1]
    reports = list(map(json.loads, capsys.readouterr().out.splitlines()))
    assert reports[0]['flags']['memory_exceeded']
    assert all(r['flags']['disk_exceeded'] for r in reports[1:-2])
    assert all(not any(r['flags'].get(k) for k in regressions.FLAGS) for r in reports[-2:])


def test_linux_resource_child_runs_resource_and_ptrace_candidates(monkeypatch, regressions, capsys):
    codes = []
    def execute(request, **kwargs):
        code = request['run_argv'][-1]
        codes.append(code)
        return dict(stage='run', returncode=1 if code in (regressions.SHM_WRITE, regressions.PTRACE_DENIED) else -9,
                    memory_exceeded=code == regressions.AGGREGATE_MEMORY,
                    disk_exceeded=code in regressions.DISK_CASES.values(),
                    output='ptrace denied\n' if code == regressions.PTRACE_DENIED else '',
                    timeout=False, overflow=False, output_not_decodable=False)
    monkeypatch.setattr(regressions.sys, 'argv', ['linux_regressions.py', '--memory-child'])
    monkeypatch.setattr(regressions.sys, 'platform', 'linux')
    monkeypatch.setattr(regressions.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(regressions, 'execute', execute)
    regressions.main()
    assert codes == [regressions.AGGREGATE_MEMORY, *regressions.DISK_CASES.values(), regressions.SHM_WRITE, regressions.PTRACE_DENIED]
    assert len(capsys.readouterr().out.splitlines()) == 3 + len(regressions.DISK_CASES)


@pytest.mark.parametrize('memory', [False, True])
def test_fork_accepts_signed_memory_limit(monkeypatch, regressions, memory, capsys):
    receipt = dict(stage='run', returncode=-9 if memory else 1,
                   output='' if memory else '20\n', output_not_decodable=False,
                   timeout=False, overflow=False, memory_exceeded=memory)
    monkeypatch.setattr(regressions, 'execute', lambda *args, **kwargs: receipt)
    regressions.check_failure(regressions.FORK_EXHAUSTION)
    assert json.loads(capsys.readouterr().out)['flags']['incorrect']


@pytest.mark.parametrize('returncode,output,supervisor_error,passed', [
    (1, 'ptrace denied\n', False, True),
    (0, '', False, False), (1, '', False, False),
    (-9, '', False, False), (1, 'ptrace denied\n', True, False),
])
def test_ptrace_regression_requires_specific_signed_denial(
        monkeypatch, regressions, capsys, returncode, output, supervisor_error, passed):
    receipt = dict(stage='run', returncode=returncode, output=output,
                   supervisor_error=supervisor_error, output_not_decodable=False,
                   timeout=False, overflow=False)
    monkeypatch.setattr(regressions, 'execute', lambda *a, **kw: receipt)
    if passed:
        regressions.check_failure(regressions.PTRACE_DENIED)
        assert json.loads(capsys.readouterr().out)['flags']['incorrect']
    else:
        with pytest.raises(AssertionError):
            regressions.check_failure(regressions.PTRACE_DENIED)


@pytest.mark.parametrize('outcome,status,oom_killed,passed', [
    ('receipt', 0, False, True), ('disk_receipt', 0, False, True),
    ('oom', 137, False, True), ('oom', 1, True, True), ('oom', 137, True, True),
    ('bad_exit', 1, False, False), ('setup_failure', 137, True, False),
    ('unsigned', 0, False, False), ('unclassified', 0, False, False),
    ('receipt', 1, False, False), ('timeout', 0, False, False),
    ('malformed', 1, False, False), ('inspect_failure', 137, False, False),
])
def test_docker_kernel_cases_accept_only_resource_receipt_or_sandbox_death(
        monkeypatch, regressions, capsys, outcome, status, oom_killed, passed):
    calls = []
    summaries = [{'flags': {'setup_succeeded': True}}]
    authenticated = outcome in ('receipt', 'disk_receipt', 'unclassified', 'timeout')
    if authenticated:
        summaries.append({'flags': {'authenticated': True, 'expected': True,
            'memory_exceeded': outcome in ('receipt', 'timeout'),
            'disk_exceeded': outcome == 'disk_receipt',
            'timeout': outcome == 'timeout', 'PRIVATE': 'candidate-secret'}})
    if outcome == 'setup_failure':
        summaries = []

    def invoke(command, **kwargs):
        calls.append(command)
        if command[1] == 'inspect':
            return SimpleNamespace(returncode=1 if outcome == 'inspect_failure' else 0,
                                   stdout='true\n' if oom_killed else 'false\n')
        return SimpleNamespace(returncode=status, stderr='candidate-secret',
            stdout='candidate-secret' if outcome == 'malformed' else '\n'.join(map(json.dumps, summaries)))

    monkeypatch.setattr(regressions, 'invoke', invoke)
    for case in regressions.KERNEL_CASES:
        if passed:
            regressions.docker_kernel_check('docker', 'image', case)
        else:
            with pytest.raises(SystemExit):
                with regressions.check(case + ':docker'):
                    regressions.docker_kernel_check('docker', 'image', case)
    runs = calls[::3]
    assert [c[-2:] for c in runs] == [['--kernel-child', case] for case in regressions.KERNEL_CASES]
    assert len({c[c.index('--name') + 1] for c in runs}) == 3
    assert all('--memory=2g' in c and '--memory-swap=2g' in c and '--rm' not in c for c in runs)
    for run, inspect, cleanup in zip(runs, calls[1::3], calls[2::3]):
        name = run[run.index('--name') + 1]
        assert inspect == ['docker', 'inspect', '--format', '{{.State.OOMKilled}}', name]
        assert cleanup == ['docker', 'rm', '-f', '-v', name]
    output = capsys.readouterr().out
    assert 'PRIVATE' not in output and 'candidate-secret' not in output
    reports = [json.loads(line) for line in output.splitlines()]
    diagnostics = [r for r in reports if 'error' not in r]
    assert len(diagnostics) == 3
    for case, report in zip(regressions.KERNEL_CASES, diagnostics):
        assert report['step'] == case + ':docker'
        assert report['returncode'] == status
        flags = report['flags']
        assert all(type(value) is bool for value in flags.values())
        assert flags['authenticated'] == authenticated
        assert flags['oom_killed'] == oom_killed
        assert flags['sandbox_died'] == (status == 137 or oom_killed)
    failures = [r for r in reports if 'error' in r]
    assert len(failures) == (0 if passed else 3)
    for case, failure in zip(regressions.KERNEL_CASES, failures):
        assert failure['step'] == case + ':docker'
        if outcome == 'malformed':
            assert failure['error'] == 'JSONDecodeError'
        else:
            assert failure['error'] == 'AssertionError'
            assert failure['label'] == ('setup-success' if outcome == 'setup_failure' else
                'docker-inspect' if outcome == 'inspect_failure' else 'docker-child-success')


@pytest.mark.parametrize('case', ['sysv_shm', 'memfd_mapped', 'socketpair_queues'])
@pytest.mark.parametrize('changes,passed', [
    ({'memory_exceeded': True}, True), ({'disk_exceeded': True}, True),
    ({}, False), ({'memory_exceeded': True, 'timeout': True}, False),
    ({'memory_exceeded': True, 'returncode': 0}, False),
    ({'returncode': 0, 'output': 'sysv shm unsupported\n'}, False),
])
def test_kernel_child_requires_signed_resource_limit(
        monkeypatch, regressions, capsys, case, changes, passed):
    receipt = dict(stage='run', returncode=-9, output='candidate-secret')
    receipt.update(changes)
    monkeypatch.setattr(regressions.sys, 'argv', ['linux_regressions.py', '--kernel-child', case])
    monkeypatch.setattr(regressions.sys, 'platform', 'linux')
    monkeypatch.setattr(regressions.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(regressions, 'execute', lambda *a, **kw: receipt)
    if passed:
        regressions.main()
    else:
        with pytest.raises(SystemExit):
            regressions.main()
    output = capsys.readouterr().out
    assert 'candidate-secret' not in output
    reports = list(map(json.loads, output.splitlines()))
    assert reports[0]['flags']['authenticated'] is True
    assert reports[0]['flags']['expected'] == passed
    if not passed:
        assert reports[1]['step'] == case + ':docker-child'
        assert reports[1]['label'] == 'failure-classified'


def test_kernel_candidates_use_retained_sinks_and_compile(regressions):
    for name, code in regressions.KERNEL_CASES.items():
        compile(code, name, 'exec')  # Never execute memory hogs on the test host.
    assert 'libc.shmdt(address)' in regressions.SYSV_SHM
    assert 'libc.shmctl' not in regressions.SYSV_SHM
    assert 'libc.mmap(None, 4096, 0, 1, fd, 0)' in regressions.MEMFD_MAPPED
    assert 'os.close(fd)' in regressions.MEMFD_MAPPED
    assert 'socket.socketpair()' in regressions.SOCKETPAIR_QUEUES


@pytest.mark.parametrize('outcome', ['signed', 'runner_137', 'missing', 'setup_failure'])
def test_disposable_child_authenticates_or_exits_137_only_after_setup(monkeypatch, regressions, capsys, outcome):
    key = bytes(range(32))
    calls = []
    from test_scoring import signed_receipt
    def invoke(command, **kwargs):
        calls.append(command)
        if regressions.SETUP in command:
            return SimpleNamespace(returncode=1 if outcome == 'setup_failure' else 0,
                stdout=json.dumps(dict(cwd='/tmp/cjt-disposable', key=key.hex())))
        if regressions.RUNNER in command:
            return SimpleNamespace(returncode=137 if outcome == 'runner_137' else 0,
                stdout=signed_receipt(key, '/tmp/cjt-disposable', returncode=-9, memory_exceeded=True)
                if outcome == 'signed' else '')
        assert command == regressions.QUIESCENCE_CHECK_COMMAND
        return SimpleNamespace(returncode=0, stdout='')
    monkeypatch.setattr(regressions, 'invoke', invoke)
    if outcome == 'signed':
        receipt = regressions.execute(regressions.request_for(regressions.MEMFD_MAPPED), disposable=True)
        assert receipt['memory_exceeded']
    elif outcome == 'runner_137':
        with pytest.raises(SystemExit) as raised:
            regressions.execute(regressions.request_for(regressions.MEMFD_MAPPED), disposable=True)
        assert raised.value.code == 137
    else:
        with pytest.raises(AssertionError):
            regressions.execute(regressions.request_for(regressions.MEMFD_MAPPED), disposable=True)
    output = capsys.readouterr().out
    assert output == ('' if outcome == 'setup_failure' else '{"flags": {"setup_succeeded": true}}\n')
    assert not any(command == regressions.CLEANUP_COMMAND for command in calls)
    assert key.hex() not in output


def test_docker_main_runs_kernel_cases_last(monkeypatch, regressions):
    events = []
    monkeypatch.setattr(regressions.sys, 'argv', ['linux_regressions.py', '--image', 'image', '--docker-cli', 'docker'])
    monkeypatch.setattr(regressions.sys, 'platform', 'linux')
    monkeypatch.setattr(regressions.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(regressions, 'compiler_smokes', lambda: events.append('compilers'))
    monkeypatch.setattr(regressions, 'check_failure', lambda *args, **kwargs: events.append('watchdog'))
    monkeypatch.setattr(regressions, 'docker_memory_check', lambda *args: events.append('docker_watchdogs'))
    monkeypatch.setattr(regressions, 'docker_kernel_check', lambda docker, image, case: events.append(case))
    regressions.main()
    assert events[-4:] == ['docker_watchdogs', *regressions.KERNEL_CASES]
