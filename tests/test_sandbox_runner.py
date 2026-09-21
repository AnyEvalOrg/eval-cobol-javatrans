"""Authored fixtures only. macOS stubs test protocol mechanics, not containment."""
import ast
from functools import partial
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import pytest
from cobol_javatrans.sandbox_runner import SETUP, RUNNER, CLEANUP_COMMAND, QUIESCENCE_COMMAND
from cobol_javatrans.scoring import verify_receipt


def prepare(request, real_supervisor=False):
    # Host protocol fixtures explicitly bypass Linux prerequisites; dedicated
    # monkeypatched tests below exercise the real setup probe and failure path.
    source = SETUP if real_supervisor else SETUP.replace('    check_prerequisites(work)', '    pass')
    result = subprocess.run([sys.executable, '-I', '-c', source], input=json.dumps(request),
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == 0
    return json.loads(result.stdout)


def run_fixture(compile_code='pass', run_code="print('ok')", timeout=1, output_file=None,
                real_supervisor=False, transform=None):
    request = dict(files={'fixture.txt': 'safe authored input'}, argv=[sys.executable, '-I', '-c', compile_code],
                   run_argv=[sys.executable, '-I', '-c', run_code], timeout=timeout, run_timeout=timeout, output_limit=4096)
    if output_file:
        request['output_file'] = output_file
    setup = prepare(request, real_supervisor=real_supervisor)
    source = RUNNER
    if not real_supervisor:
        # Never perform credential changes or UID sweeps on the developer host.
        # Keep file-size limits, overflow detection, and stage gating intact.
        source = source.replace('libc = ctypes.CDLL(None, use_errno=True)', 'libc = type("Stub", (), {"prctl": lambda *args: 0})()')
        source = source.replace('os.getuid() != 0', 'False')
        source = source.replace('with open("/proc/self/oom_score_adj", "w") as f:', 'with open(os.devnull, "w") as f:')
        source = source.replace('    candidate_limits(java)',
                                '    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))')
        source = source.replace('os.setgroups([])', 'pass')
        source = source.replace('os.setresgid(CANDIDATE_GID, CANDIDATE_GID, CANDIDATE_GID)', 'pass')
        source = source.replace('os.setresuid(CANDIDATE_UID, CANDIDATE_UID, CANDIDATE_UID)', 'pass')
        source = source.replace('os.chown(candidate_work, CANDIDATE_UID, CANDIDATE_GID)', 'pass')
        source = source.replace('info.st_uid != CANDIDATE_UID', 'info.st_uid != os.getuid()')
        source = source.replace('os.killpg(pgid, sig)', 'os.kill(pgid, sig)')
        start, end = source.index('def memory_watchdog('), source.index('def run_step(')
        source = source[:start] + 'def memory_watchdog(*args):\n    pass\n\ndef disk_watchdog(*args):\n    pass\n\ndef sweep_uid():\n    pass\n\n\n' + source[end:]
    if transform:
        source = transform(source)
    try:
        with tempfile.TemporaryFile() as published:
            result = subprocess.run([sys.executable, '-I', '-c', source, setup['cwd']],
                                    stdout=published, stderr=subprocess.PIPE, text=True, timeout=8)
            assert result.returncode == 0, result.stderr
            published.seek(0)
            receipt = verify_receipt(published.read().decode(), bytes.fromhex(setup['key']))
        assert receipt is not None
        if not transform:
            assert Path(setup['cwd']).exists()
        return receipt
    finally:
        shutil.rmtree(setup['cwd'], ignore_errors=True)


@pytest.fixture
def output_limit_runner():
    """Use the real supervisor under the Linux containment suite's opt-in."""
    real = sys.platform == 'linux' and os.geteuid() == 0 and os.environ.get('CJT_LINUX_CONTAINMENT') == '1'
    if real:
        result = subprocess.run(['/usr/bin/pgrep', '-u', '65532'], capture_output=True, timeout=5)
        assert result.returncode == 1, 'candidate UID must be unused before containment tests'
    try:
        yield partial(run_fixture, real_supervisor=real)
    finally:
        if real:
            for command in (CLEANUP_COMMAND, QUIESCENCE_COMMAND):
                result = subprocess.run(command, capture_output=True, timeout=6)
                assert result.returncode in ((0, 1) if command == CLEANUP_COMMAND else (0,))


def overflowing_writer(target):
    # Attempt twice the 4096-byte request limit. Ignore SIGXFSZ and handle EFBIG
    # so a successful child exit forces the supervisor to detect the overflow.
    # Report stderr's size via stdout, since stderr is absent from the receipt.
    return f'''import errno, os, signal
signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
fd = {target}
remaining = b'x' * 8192
try:
    while remaining:
        remaining = remaining[os.write(fd, remaining):]
except OSError as exc:
    if exc.errno != errno.EFBIG:
        raise
if fd == 2:
    print(os.fstat(fd).st_size)
'''


@pytest.mark.parametrize('stream, expected_output', [('stdout', 'x' * 4096), ('stderr', '4096\n')],
                         ids=['stdout', 'stderr'])
def test_compile_output_limit_blocks_execution(output_limit_runner, stream, expected_output):
    receipt = output_limit_runner(
        compile_code=overflowing_writer('1' if stream == 'stdout' else '2'),
        run_code="print('MUST_NOT_RUN')",
    )
    assert receipt['returncode'] == 0 and not receipt['timeout']
    assert receipt['overflow'] is True
    assert receipt['stage'] == 'compile'
    assert 'MUST_NOT_RUN' not in receipt['output']
    assert receipt['output'] == expected_output


def test_result_file_output_limit(output_limit_runner):
    receipt = output_limit_runner(
        run_code=overflowing_writer("os.open('OUT.TXT', os.O_WRONLY | os.O_CREAT, 0o600)"),
        output_file='OUT.TXT',
    )
    assert receipt['returncode'] == 0 and not receipt['timeout']
    assert receipt['stage'] == 'run'
    assert receipt['overflow'] is True
    assert receipt['output'] == 'x' * 4096


def test_setup_atomic_private_dirs_and_keys():
    setups = [prepare(dict(files={}, argv=['true'], timeout=1, output_limit=4096)) for _ in range(2)]
    try:
        assert len({s['cwd'] for s in setups}) == len({s['key'] for s in setups}) == 2
        for s in setups:
            assert Path(s['cwd']).stat().st_mode & 0o777 == 0o700
            assert (Path(s['cwd'])/'request.json').is_file()
    finally:
        for s in setups:
            shutil.rmtree(s['cwd'])


def test_separate_steps_share_workdir_and_request_is_unlinked():
    receipt = run_fixture("open('artifact','w').write('ok')", "import os; assert not os.path.exists('../request.json'); print(open('artifact').read())")
    assert receipt['returncode'] == 0 and receipt['stage'] == 'run'
    assert receipt['output'] == 'ok\n'


def test_compile_failure_never_executes_run_step():
    receipt = run_fixture('raise SystemExit(7)', "print('MUST_NOT_RUN')")
    assert receipt['stage'] == 'compile' and receipt['returncode'] == 7
    assert 'MUST_NOT_RUN' not in receipt['output']


def test_compile_only_success_retains_compile_stage():
    receipt = run_fixture(transform=lambda source: source.replace(
        'key = bytes.fromhex', "request.pop('run_argv')\nkey = bytes.fromhex"))
    assert receipt['stage'] == 'compile' and receipt['returncode'] == 0
    from cobol_javatrans.receipt import receipt_failure
    assert receipt_failure(receipt) == 'run did not complete.'


@pytest.mark.parametrize('state,uid,expected', [
    ('Z', '65532', 0), ('X', '65532', 0), ('S', '65532', 2),
    ('R', '65532', 2), ('S', '0', 0),
])
def test_quiescence_preflight_ignores_only_dead_or_other_uid(monkeypatch, state, uid, expected):
    import io
    from cobol_javatrans.sandbox_runner import UID_QUIESCENCE, QUIESCENCE_CHECK_COMMAND
    monkeypatch.setattr(sys, 'argv', ['-c', '--check-only'])
    monkeypatch.setattr(os, 'listdir', lambda path: ['self', '123', '456'])

    def read_status(path):
        if path == '/proc/456/status':
            raise FileNotFoundError  # Process exited between enumeration and read.
        assert path == '/proc/123/status'
        return io.StringIO(f'Uid:\t{uid}\t{uid}\t{uid}\t{uid}\nState:\t{state} (fixture)\n')

    def forbidden_sweep(*args, **kwargs):
        pytest.fail('preflight must not kill any processes')

    monkeypatch.setattr('builtins.open', read_status)
    monkeypatch.setattr(subprocess, 'run', forbidden_sweep)
    assert QUIESCENCE_CHECK_COMMAND == QUIESCENCE_COMMAND + ['--check-only']
    if expected:
        with pytest.raises(SystemExit) as stopped:
            exec(UID_QUIESCENCE, {})
        assert stopped.value.code == expected
    else:
        exec(UID_QUIESCENCE, {})


def test_quiescence_repeats_sweeps_until_only_zombies_remain(monkeypatch):
    import io
    import time
    from types import SimpleNamespace
    from cobol_javatrans.sandbox_runner import UID_QUIESCENCE
    sweeps = []
    monkeypatch.setattr(sys, 'argv', ['-c'])
    monkeypatch.setattr(os, 'listdir', lambda path: ['123'])
    monkeypatch.setattr(time, 'sleep', lambda delay: None)

    def sweep(command, **kwargs):
        sweeps.append(command)
        return SimpleNamespace(returncode=0)

    def read_status(path):
        state = 'S' if len(sweeps) == 1 else 'Z'
        return io.StringIO(f'Uid:\t65532\t65532\t65532\t65532\nState:\t{state}\n')

    monkeypatch.setattr(subprocess, 'run', sweep)
    monkeypatch.setattr('builtins.open', read_status)
    exec(UID_QUIESCENCE, {})
    assert sweeps == [['/usr/bin/pkill', '-KILL', '-u', '65532']] * 2


def test_forged_marker_cannot_override_exit():
    receipt = run_fixture(run_code="print('<completed-sentinel-value-0>'); raise SystemExit(7)")
    assert receipt['stage'] == 'run' and receipt['returncode'] == 7


@pytest.mark.parametrize('stage', ['compile', 'run'])
def test_each_stage_has_independent_timeout(stage):
    kwargs = {'compile_code' if stage == 'compile' else 'run_code': 'while True: pass'}
    receipt = run_fixture(timeout=0.1, **kwargs)
    assert receipt['timeout'] and receipt['stage'] == stage
    assert receipt['returncode'] != 0


def test_output_file_receipt():
    receipt = run_fixture(run_code="open('OUT.TXT','w').write('p23\\n')", output_file='OUT.TXT')
    assert receipt['output'] == 'p23\n' and receipt['returncode'] == 0


@pytest.mark.parametrize('code', ["import os; os.symlink('/etc/passwd','OUT.TXT')", "import os; os.mkfifo('OUT.TXT')", 'pass'])
def test_unsafe_or_missing_output_files_fail_without_reading(code):
    receipt = run_fixture(run_code=code, output_file='OUT.TXT')
    assert receipt['returncode'] != 0 and receipt['output'] == ''


def test_supervisor_preserves_required_security_contract():
    tree = ast.parse(RUNNER)
    restrict = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'restrict_child')
    calls = [ast.unparse(n.value) for n in restrict.body if isinstance(n, ast.Expr)]
    assert calls.index('os.setgroups([])') < calls.index('os.setresgid(CANDIDATE_GID, CANDIDATE_GID, CANDIDATE_GID)') < calls.index('os.setresuid(CANDIDATE_UID, CANDIDATE_UID, CANDIDATE_UID)') < calls.index('candidate_limits(java)')
    for text in ['libc.prctl(4, 0, 0, 0, 0)', 'libc.prctl(38, 1, 0, 0, 0)', 'libc.prctl(8, 0, 0, 0, 0)', 'libc.prctl(36, 1, 0, 0, 0)', 'os.killpg(pgid, sig)', 'os.O_NOFOLLOW', 'sweep_uid()', 'close_fds=True', 'start_new_session=True', 'preexec_fn=lambda: restrict_child(java)', 'os.unlink(request_path)']:
        assert text in RUNNER
    assert 'shell=True' not in RUNNER and 'bash' not in RUNNER
    assert CLEANUP_COMMAND[-4:] == ['/usr/bin/pkill', '-KILL', '-u', '65532']


@pytest.mark.parametrize('output_file', [None, 'OUT.TXT'])
def test_invalid_utf8_retains_authenticated_receipt(output_file):
    code = "import os; os.write(1, bytes([255])); raise SystemExit(1)"
    if output_file:
        code = "open('OUT.TXT', 'wb').write(bytes([255]))"
    receipt = run_fixture(run_code=code, output_file=output_file)
    assert receipt['stage'] == 'run'
    assert receipt['output_not_decodable'] is True
    from cobol_javatrans.receipt import receipt_failure
    assert receipt_failure(receipt) == 'output not decodable.'


@pytest.mark.parametrize('failed_step', ['kill_group', 'sweep_uid', 'read'])
def test_post_exit_exceptions_cannot_erase_receipt(failed_step):
    def transform(source):
        if failed_step == 'read':
            source = source.replace('output = stdout.read(limit + 1)', 'raise OSError("read failed")')
        else:
            name = 'def ' + failed_step + '('
            start = source.index(name)
            body = source.index('\n', start) + 1
            source = source[:body] + '    raise OSError("no process slots")\n' + source[body:]
        return source
    receipt = run_fixture(compile_code='raise SystemExit(7)', transform=transform)
    assert receipt['returncode'] == 7
    assert receipt['stage'] == 'compile'
    if failed_step in {'kill_group', 'sweep_uid'}:
        assert receipt['cleanup_failed']
    if failed_step == 'read':
        assert receipt['supervisor_error']


@pytest.mark.parametrize('java', [False, True])
@pytest.mark.parametrize('inherited', [None, 384 * 1024**2])
def test_actual_candidate_limits_function(java, inherited):
    from types import SimpleNamespace
    import resource
    limits = {}
    fake = SimpleNamespace(**{name: getattr(resource, name) for name in
        ('RLIMIT_NPROC', 'RLIMIT_NOFILE', 'RLIMIT_AS', 'RLIMIT_DATA', 'RLIMIT_FSIZE', 'RLIMIT_CORE', 'RLIM_INFINITY')})
    fake.getrlimit = lambda kind: (inherited, inherited) if inherited and kind in (resource.RLIMIT_AS, resource.RLIMIT_DATA) else (resource.RLIM_INFINITY, resource.RLIM_INFINITY)
    fake.setrlimit = lambda kind, values: limits.__setitem__(kind, values)
    tree = ast.parse(RUNNER)
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'candidate_limits')
    ns = {'resource': fake, 'limit': 4096}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), '<limits>', 'exec'), ns)
    ns['candidate_limits'](java)
    memory = inherited or (8 * 1024**3 if java else 1024**3)
    assert limits == {resource.RLIMIT_NPROC: (64, 64), resource.RLIMIT_AS: (memory, memory),
                      resource.RLIMIT_DATA: (memory, memory), resource.RLIMIT_FSIZE: (4096, 4096),
                      resource.RLIMIT_CORE: (0, 0),
                      resource.RLIMIT_NOFILE: (1024, 1024) if java else (256, 256)}


def test_oom_preference_is_set_as_root_before_credential_drop():
    tree = ast.parse(RUNNER)
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'restrict_child')
    source = ast.unparse(fn)
    assert source.index("open('/proc/self/oom_score_adj', 'w')") < source.index('os.setresuid(')
    assert "f.write('1000')" in source


@pytest.mark.parametrize('executable,java', [('javac', True), ('java', True), ('cobc', False), ('./call', False)])
def test_step_applies_jvm_environment_and_matching_preexec_limits(tmp_path, executable, java):
    from types import SimpleNamespace
    calls = []
    modes = []

    def popen(argv, **kwargs):
        calls.append((argv, kwargs))
        kwargs['preexec_fn']()
        return SimpleNamespace(pid=123, wait=lambda **kwargs: 0)

    tree = ast.parse(RUNNER)
    nodes = [n for n in tree.body if
             (isinstance(n, ast.FunctionDef) and n.name == 'run_step') or
             (isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'JAVA_TOOL_OPTIONS' for t in n.targets))]
    ns = dict(os=os, tempfile=tempfile, threading=threading, memory_watchdog=lambda *args: None, disk_watchdog=lambda *args: None, work=str(tmp_path), limit=4096,
              subprocess=SimpleNamespace(Popen=popen, DEVNULL=subprocess.DEVNULL, TimeoutExpired=subprocess.TimeoutExpired),
              restrict_child=modes.append, kill_group=lambda pid: None, sweep_uid=lambda: None)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<step>', 'exec'), ns)
    status, _ = ns['run_step']([executable], 1, str(tmp_path))
    assert status['returncode'] == 0 and not status['supervisor_error']
    assert modes == [java]
    env = calls[0][1]['env']
    if java:
        assert env['JAVA_TOOL_OPTIONS'] == '-Xmx512m -XX:MaxMetaspaceSize=256m -XX:ReservedCodeCacheSize=64m -Xss1m -XX:-UsePerfData'
    else:
        assert 'JAVA_TOOL_OPTIONS' not in env


@pytest.mark.parametrize('rss_kib, trips', [(768 * 1024, False), (768 * 1024 + 1, True)])
def test_memory_watchdog_aggregate_proc_data(monkeypatch, rss_kib, trips):
    import io
    import signal
    from types import SimpleNamespace
    calls = []
    statuses = {
        '/proc/1/status': 'Uid: 0 0 0 0\nVmRSS: 9999999 kB\n',
        '/proc/2/status': f'Uid: 65532 65532 65532 65532\nVmRSS: {rss_kib // 2} kB\n',
        '/proc/3/status': f'Uid: 65532 65532 65532 65532\nVmRSS: {rss_kib - rss_kib // 2} kB\n',
        '/proc/4/status': 'Uid: 65532 65532 65532 65532\nState: Z\n',
    }
    def read(path):
        if path not in statuses:
            raise FileNotFoundError(path)
        return io.StringIO(statuses[path])
    fake_os = SimpleNamespace(listdir=lambda p: ['1', '2', '3', '4', '5', 'self'],
                              killpg=lambda *a: calls.append(('group', *a)),
                              kill=lambda *a: calls.append(('pid', *a)))
    class Stop:
        done = False
        def is_set(self): return self.done
        def wait(self, interval):
            assert interval == 0.05
            self.done = True
    nodes = [n for n in ast.parse(RUNNER).body if isinstance(n, ast.FunctionDef)
             and n.name in ('candidate_processes', 'memory_watchdog', 'kill_candidate')]
    ns = dict(os=fake_os, open=read, signal=signal, CANDIDATE_UID=65532,
              AGGREGATE_MEMORY=768 * 1024**2, WATCHDOG_INTERVAL=0.05)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<watchdog>', 'exec'), ns)
    status = {'memory_exceeded': False, 'supervisor_error': False}
    ns['memory_watchdog'](2, Stop(), status)
    assert status == {'memory_exceeded': trips, 'supervisor_error': False}
    assert calls == ([('group', 2, signal.SIGKILL)] +
                     [('pid', p, signal.SIGKILL) for p in (2, 3, 4)] if trips else [])


@pytest.mark.parametrize('hang', [False, True])
def test_receipt_complete_without_attempting_directory_deletion(hang):
    def transform(source):
        # A deletion would either terminate with no receipt or hang past the
        # fixture deadline. Both must be unreachable in the supervisor process.
        injection = """
import shutil
def forbidden_delete(*args, **kwargs):
    if HANG:
        while True: time.sleep(1)
    os._exit(99)
shutil.rmtree = forbidden_delete
""".replace('HANG', repr(hang))
        return source.replace('work = sys.argv[1]', injection + '\nwork = sys.argv[1]')
    receipt = run_fixture(transform=transform)
    assert receipt['returncode'] == 0 and receipt['output'] == 'ok\n'
    tree = ast.parse(RUNNER)
    final = tree.body[-1].finalbody
    assert ast.unparse(final[-2]) == 'sys.stdout.flush()'
    assert ast.unparse(final[-1]) == 'os._exit(0)'
    assert 'rmtree' not in RUNNER


@pytest.mark.parametrize('watchdog,flag', [('memory_watchdog', 'memory_exceeded'),
                                          ('disk_watchdog', 'disk_exceeded')])
def test_watchdog_flag_is_signed_and_blocks_next_stage(watchdog, flag):
    def transform(source):
        return source.replace(f'def {watchdog}(*args):\n    pass',
                              f'def {watchdog}(pgid, stopped, status):\n    status[{flag!r}] = True')
    receipt = run_fixture(run_code="print('MUST_NOT_RUN')", transform=transform)
    assert receipt['stage'] == 'compile'
    assert receipt[flag] is True
    assert receipt['output'] == ''


@pytest.mark.parametrize('trips', [False, True])
def test_disk_watchdog_counts_allocated_blocks_across_trees(tmp_path, trips):
    import errno
    import signal
    import stat
    roots = [tmp_path / 'tmp', tmp_path / 'shm']
    work = roots[0] / 'cjt-work' / 'candidate'
    sibling = roots[0] / 'cjt-other'
    for directory in (work, sibling, roots[1]):
        directory.mkdir(parents=True)
        (directory / 'data').write_bytes(os.urandom(8192))
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'ignored').write_bytes(os.urandom(8192))
    (work / 'file-link').symlink_to(outside / 'ignored')
    (sibling / 'dir-link').symlink_to(outside, target_is_directory=True)
    (sibling / 'loop').symlink_to(roots[0], target_is_directory=True)
    os.mkfifo(work / 'fifo')
    with (work / 'sparse').open('wb') as stream:
        stream.truncate(1024**3)
    expected = sum(p.stat().st_blocks * 512 for p in
                   (work / 'data', sibling / 'data', roots[1] / 'data', work / 'sparse'))
    nodes = [n for n in ast.parse(RUNNER).body if isinstance(n, ast.FunctionDef)
             and n.name in ('disk_usage', 'disk_watchdog', 'kill_candidate')]
    calls = []
    class Stop:
        done = False
        def is_set(self): return self.done
        def wait(self, interval):
            assert interval == 0.1
            self.done = True
    ns = dict(os=os, stat=stat, errno=errno, signal=signal,
              AGGREGATE_DISK=expected - int(trips), DISK_ENTRY_LIMIT=10000, DISK_WATCHDOG_INTERVAL=0.1,
              candidate_processes=lambda: [])
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<disk-watchdog>', 'exec'), ns)
    usage = ns['disk_usage']
    assert usage(roots) == expected
    assert usage([tmp_path / 'missing', work / 'data', sibling / 'dir-link']) == 0
    ns['disk_usage'] = lambda **kwargs: usage(roots, **kwargs)
    # Exercise the shared kill path, without scanning/signaling host processes.
    ns['kill_candidate'] = partial(ns['kill_candidate'], processes=[(124, 0)])
    from types import SimpleNamespace
    ns['os'] = SimpleNamespace(**{name: getattr(os, name) for name in
        ('open', 'close', 'scandir', 'stat', 'O_RDONLY', 'O_DIRECTORY', 'O_NOFOLLOW')},
        killpg=lambda *args: calls.append(('group', *args)),
        kill=lambda *args: calls.append(('pid', *args)))
    status = dict(disk_exceeded=False, supervisor_error=False)
    ns['disk_watchdog'](123, Stop(), status)
    assert status == dict(disk_exceeded=trips, supervisor_error=False)
    assert calls == ([('group', 123, signal.SIGKILL), ('pid', 124, signal.SIGKILL)] if trips else [])


def test_disk_watchdog_fails_closed_on_scan_error():
    from types import SimpleNamespace
    nodes = [n for n in ast.parse(RUNNER).body if isinstance(n, ast.FunctionDef)
             and n.name == 'disk_watchdog']
    def broken_scan(**kwargs):
        raise PermissionError('scan failed')
    killed = []
    ns = dict(disk_usage=broken_scan, kill_candidate=killed.append)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<disk-watchdog>', 'exec'), ns)
    status = dict(disk_exceeded=False, supervisor_error=False)
    ns['disk_watchdog'](123, SimpleNamespace(is_set=lambda: False), status)
    assert status == dict(disk_exceeded=False, supervisor_error=True)
    assert killed == [123]


@pytest.mark.parametrize('replacement', ['deleted', 'symlink'])
def test_disk_walk_tolerates_directory_replacement_without_following(tmp_path, replacement):
    import errno
    import stat
    from types import SimpleNamespace
    root = tmp_path / 'root'
    root.mkdir()
    moving = root / 'moving'
    moving.mkdir()
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'ignored').write_bytes(os.urandom(8192))
    stable = root / 'stable'
    stable.write_bytes(os.urandom(8192))
    opened = []
    def racing_open(path, flags, **kwargs):
        if path == 'moving':
            opened.append(path)
            moving.rmdir()
            if replacement == 'symlink':
                moving.symlink_to(outside, target_is_directory=True)
        return os.open(path, flags, **kwargs)
    fake_os = SimpleNamespace(**{name: getattr(os, name) for name in
        ('close', 'scandir', 'O_RDONLY', 'O_DIRECTORY', 'O_NOFOLLOW')}, open=racing_open)
    node = next(n for n in ast.parse(RUNNER).body if isinstance(n, ast.FunctionDef)
                and n.name == 'disk_usage')
    ns = dict(os=fake_os, stat=stat, errno=errno, AGGREGATE_DISK=256 * 1024**2,
              DISK_ENTRY_LIMIT=10000, candidate_processes=lambda: [])
    exec(compile(ast.Module(body=[node], type_ignores=[]), '<disk-race>', 'exec'), ns)
    assert ns['disk_usage']([root]) == stable.stat().st_blocks * 512
    assert opened == ['moving']


def disk_namespace(**overrides):
    import errno
    import stat
    ns = dict(os=os, stat=stat, errno=errno, AGGREGATE_DISK=256 * 1024**2,
              DISK_ENTRY_LIMIT=10000, candidate_processes=lambda: [])
    ns.update(overrides)
    node = next(n for n in ast.parse(RUNNER).body if isinstance(n, ast.FunctionDef)
                and n.name == 'disk_usage')
    exec(compile(ast.Module(body=[node], type_ignores=[]), '<disk-usage>', 'exec'), ns)
    return ns


def test_disk_counts_unlinked_and_memfd_descriptors_once(tmp_path):
    import stat
    from contextlib import nullcontext
    from types import SimpleNamespace
    visible = tmp_path / 'visible'
    visible.write_bytes(os.urandom(8192))
    (tmp_path / 'hardlink').hardlink_to(visible)
    with tempfile.TemporaryFile(dir=tmp_path) as retained:
        retained.write(os.urandom(16384))
        retained.flush()
        # Procfs magic-link stat results, including an anonymous memfd and a
        # pipe that must be ignored. Repeated fds across processes count once.
        memfd = SimpleNamespace(st_mode=stat.S_IFREG, st_blocks=32, st_dev=777, st_ino=9)
        infos = {'0': visible.stat(), '1': os.fstat(retained.fileno()), '2': memfd,
                 '3': memfd, '4': SimpleNamespace(st_mode=stat.S_IFIFO, st_dev=778, st_ino=1)}
        real_scandir = os.scandir
        paths = []
        def scandir(path):
            if isinstance(path, str) and path.startswith('/proc/'):
                return nullcontext(iter(SimpleNamespace(path=path + '/' + name)
                                        for name in [*infos, 'closed']))
            return real_scandir(path)
        def proc_stat(path):
            paths.append(path)
            if path.endswith('/closed'):
                raise FileNotFoundError(2, 'descriptor closed')
            return infos[path.rsplit('/', 1)[-1]]
        fake_os = SimpleNamespace(**{name: getattr(os, name) for name in
            ('open', 'close', 'O_RDONLY', 'O_DIRECTORY', 'O_NOFOLLOW')},
            scandir=scandir, stat=proc_stat)
        ns = disk_namespace(os=fake_os, candidate_processes=lambda: [(2, 0), (3, 0)])
        expected = sum(info.st_blocks * 512 for info in (infos['0'], infos['1'], memfd))
        assert ns['disk_usage']([tmp_path]) == expected
        assert len(paths) == 12


@pytest.mark.parametrize('stop_after', [0, 17, None])
def test_disk_scan_cancels_and_stops_at_inode_budget(stop_after):
    import stat
    from contextlib import nullcontext
    from types import SimpleNamespace
    visited = []
    def entries():
        for i in range(50000):
            visited.append(i)
            yield SimpleNamespace(stat=lambda **kw: SimpleNamespace(
                st_mode=stat.S_IFREG, st_dev=1, st_ino=i, st_blocks=0))
    fake_os = SimpleNamespace(O_RDONLY=0, O_DIRECTORY=0, O_NOFOLLOW=0,
                              open=lambda *a, **kw: 1, close=lambda fd: None,
                              scandir=lambda fd: nullcontext(entries()))
    stopped = SimpleNamespace(is_set=lambda: stop_after is not None and len(visited) >= stop_after)
    ns = disk_namespace(os=fake_os)
    usage = ns['disk_usage'](['/synthetic'], stopped=stopped)
    assert len(visited) == (10001 if stop_after is None else stop_after)
    assert (usage > ns['AGGREGATE_DISK']) is (stop_after is None)


def test_disk_scan_stops_at_byte_budget(tmp_path):
    for i in range(100):
        (tmp_path / str(i)).write_bytes(os.urandom(8192))
    one_file = (tmp_path / '0').stat().st_blocks * 512
    ns = disk_namespace(AGGREGATE_DISK=one_file)
    assert ns['disk_usage']([tmp_path]) == 2 * one_file


@pytest.mark.parametrize('blocked_stat', [False, True])
def test_50k_entry_tree_cannot_delay_signed_receipt(blocked_stat):
    import time
    # Keep the actual disk scanner/watchdog and signing path, replacing only
    # host containment and the tree with 50k synthetic empty directory entries.
    # A blocked stat additionally proves even uncancellable I/O cannot delay sign.
    def transform(source):
        nodes = [n for n in ast.parse(RUNNER).body if isinstance(n, ast.FunctionDef)
                 and n.name in ('disk_usage', 'disk_watchdog')]
        monitoring = '\n\n'.join(ast.unparse(n) for n in nodes)
        fixture = '''
from contextlib import contextmanager
from types import SimpleNamespace
@contextmanager
def synthetic_tree(fd):
    def entries():
        for i in range(50000):
            def info(**kwargs):
                if BLOCKED: time.sleep(60)
                return SimpleNamespace(st_mode=stat.S_IFREG, st_blocks=0, st_dev=1, st_ino=i)
            yield SimpleNamespace(stat=info)
    yield entries()
os.scandir = synthetic_tree
def candidate_processes():
    return []
def kill_candidate(pgid):
    try: os.kill(pgid, signal.SIGKILL)
    except ProcessLookupError: pass
'''.replace('BLOCKED', repr(blocked_stat))
        monitoring = monitoring.replace("roots=('/tmp', '/var/tmp', '/dev/shm')", 'roots=(work,)')
        return source.replace('def run_step(', monitoring + '\n' + fixture + '\ndef run_step(')
    started = time.monotonic()
    receipt = run_fixture(compile_code='import time; time.sleep(0.5)',
                          run_code="print('MUST_NOT_RUN')", transform=transform)
    assert time.monotonic() - started < 3
    assert receipt['stage'] == 'compile'
    assert receipt['supervisor_error'] is blocked_stat
    assert receipt['disk_exceeded'] is (not blocked_stat)
    assert 'MUST_NOT_RUN' not in receipt['output']


def test_both_stuck_watchdogs_have_bounded_joins():
    import time
    def transform(source):
        for name in ('memory_watchdog', 'disk_watchdog'):
            source = source.replace(f'def {name}(*args):\n    pass',
                                    f'def {name}(*args):\n    time.sleep(60)')
        return source
    started = time.monotonic()
    receipt = run_fixture(transform=transform)
    assert time.monotonic() - started < 3
    assert receipt['supervisor_error']
    assert receipt['stage'] == 'compile'


@pytest.mark.parametrize('source', [SETUP, RUNNER], ids=['setup', 'runner'])
@pytest.mark.parametrize('failed_prctl', [None, 38, 8])
def test_restrict_child_drops_capabilities_in_order(source, failed_prctl):
    from types import SimpleNamespace
    from contextlib import contextmanager
    calls = []

    @contextmanager
    def opened(path, mode):
        calls.append(('open', path, mode))
        yield SimpleNamespace(write=lambda value: calls.append(('oom', value)))

    def prctl(*args):
        calls.append(('prctl', *args))
        return int(args[0] == failed_prctl)

    def exit_child(code):
        calls.append(('exit', code))
        raise SystemExit(code)

    fake_os = SimpleNamespace(
        setgroups=lambda groups: calls.append(('groups', groups)),
        setresgid=lambda *ids: calls.append(('gid', *ids)),
        setresuid=lambda *ids: calls.append(('uid', *ids)), _exit=exit_child)
    node = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef)
                and n.name == 'restrict_child')
    ns = dict(os=fake_os, libc=SimpleNamespace(prctl=prctl), open=opened,
              CANDIDATE_UID=65532, CANDIDATE_GID=65532,
              candidate_limits=lambda java: calls.append(('limits', java)))
    exec(compile(ast.Module(body=[node], type_ignores=[]), '<restrict>', 'exec'), ns)
    expected = [('open', '/proc/self/oom_score_adj', 'w'), ('oom', '1000'),
                ('prctl', 38, 1, 0, 0, 0), ('prctl', 8, 0, 0, 0, 0),
                ('groups', []), ('gid', 65532, 65532, 65532),
                ('uid', 65532, 65532, 65532), ('limits', False)]
    if failed_prctl:
        with pytest.raises(SystemExit) as stopped:
            ns['restrict_child']()
        assert stopped.value.code == 125
        expected = expected[:3 if failed_prctl == 38 else 4] + [('exit', 125)]
    else:
        ns['restrict_child']()
    assert calls == expected


@pytest.mark.parametrize('failure', [None, 'root', 'dumpable', 'proc_list', 'oom_open',
                                    'oom_write', 'work_create', 'script_write', 'spawn',
                                    'fd_stat', 'status_read', 'uid', 'rss',
                                    'work_write', 'noexec'])
def test_setup_prerequisites_fail_before_publishing_request(monkeypatch, tmp_path, failure):
    import builtins
    import ctypes
    import io
    from types import SimpleNamespace
    original_open, original_stat = builtins.open, os.stat
    launched, executed, cleanup = [], [], []
    work = tmp_path / 'cjt-probe'

    def mkdtemp(**kwargs):
        assert kwargs == dict(prefix='cjt-', dir='/tmp')
        if failure == 'work_create':
            raise PermissionError('private failure details')
        work.mkdir()
        return str(work)

    def opened(path, mode='r', **kwargs):
        path = str(path)
        if path == '/proc/self/oom_score_adj':
            assert mode == 'r+'
            if failure == 'oom_open':
                raise PermissionError('private failure details')
            class Oom(io.StringIO):
                def write(self, value):
                    if failure == 'oom_write':
                        raise PermissionError('private failure details')
                    assert value == '0\n'
                    return super().write(value)
            return Oom('0\n')
        if path == '/proc/123/status':
            if failure == 'status_read':
                raise PermissionError('private failure details')
            return io.StringIO(('Uid: 0 0 0 0\n' if failure == 'uid' else
                                'Uid: 65532 65532 65532 65532\n') +
                               ('' if failure == 'rss' else 'VmRSS: 1024 kB\n'))
        if path.endswith('/probe/check') and failure == 'script_write':
            raise PermissionError('private failure details')
        return original_open(path, mode, **kwargs)

    def proc_stat(path, **kwargs):
        if str(path) == '/proc/123/fd/0':
            if failure == 'fd_stat':
                raise PermissionError('private failure details')
            return SimpleNamespace()
        return original_stat(path, **kwargs)

    def listdir(path):
        assert path == '/proc'
        if failure == 'proc_list':
            raise PermissionError('private failure details')
        return ['1', 'self']

    def popen(command, **kwargs):
        assert command == [sys.executable, '-I', '-c', 'import time; time.sleep(2)']
        assert kwargs['preexec_fn'] is ns['restrict_child']
        assert kwargs['close_fds']
        if failure == 'spawn':
            raise subprocess.SubprocessError('private failure details')
        launched.append(command)
        return SimpleNamespace(pid=123, kill=lambda: cleanup.append('kill'),
                               wait=lambda **kw: cleanup.append('wait'))

    def run(command, **kwargs):
        assert kwargs['preexec_fn'] is ns['restrict_child']
        assert kwargs['timeout'] == 1 and kwargs['check'] and kwargs['close_fds']
        script = Path(command[0])
        assert script.read_text().startswith('#!/bin/sh\n')
        assert script.stat().st_mode & 0o111 == 0o111
        assert Path(kwargs['cwd']) == work / 'probe'
        if failure == 'noexec':
            raise PermissionError('private failure details')
        if failure == 'work_write':
            raise subprocess.CalledProcessError(1, command)
        (work / 'probe/writable').write_text('ready')
        executed.append(command)

    monkeypatch.setattr(ctypes, 'CDLL', lambda *a, **kw: SimpleNamespace(
        prctl=lambda *a: int(failure == 'dumpable')))
    monkeypatch.setattr(os, 'getuid', lambda: 1 if failure == 'root' else 0)
    monkeypatch.setattr(os, 'chown', lambda *a: None)
    monkeypatch.setattr(os, 'listdir', listdir)
    monkeypatch.setattr(os, 'stat', proc_stat)
    monkeypatch.setattr(builtins, 'open', opened)
    monkeypatch.setattr(tempfile, 'mkdtemp', mkdtemp)
    monkeypatch.setattr(subprocess, 'Popen', popen)
    monkeypatch.setattr(subprocess, 'run', run)
    monkeypatch.setattr(sys, 'stdin', io.StringIO(json.dumps(dict(files={}, output_limit=4096))))
    published = io.StringIO()
    monkeypatch.setattr(sys, 'stdout', published)
    ns = {}
    if failure:
        with pytest.raises(SystemExit) as stopped:
            exec(SETUP, ns)
        assert stopped.value.code == 'Sandbox prerequisites unavailable.'
        assert published.getvalue() == ''
        assert not (work / 'request.json').exists()
    else:
        exec(SETUP, ns)
        receipt = json.loads(published.getvalue())
        assert receipt['cwd'] == str(work)
        assert len(bytes.fromhex(receipt['key'])) == 32
        assert json.loads((work / 'request.json').read_text())['key'] == receipt['key']
        assert work.stat().st_mode & 0o777 == 0o700
        assert len(executed) == 1
    assert cleanup == (['kill', 'wait'] if launched else [])
    if launched:
        assert not (work / 'probe').exists()


@pytest.mark.parametrize('error', [PermissionError, FileNotFoundError, ProcessLookupError])
@pytest.mark.parametrize('monitor', ['memory_watchdog', 'disk_watchdog'])
def test_watchdogs_skip_unreadable_process_and_keep_scanning(error, monitor):
    import io
    from contextlib import nullcontext
    from types import SimpleNamespace
    scanned = []

    def read(path):
        scanned.append(path)
        if path == '/proc/1/status':
            raise error()
        return io.StringIO('Uid: 65532 65532 65532 65532\nVmRSS: 1024 kB\n')

    fake_os = SimpleNamespace(listdir=lambda path: ['1', '2', 'self'],
                              scandir=lambda path: nullcontext(iter([])))
    ns = disk_namespace(os=fake_os, open=read, CANDIDATE_UID=65532,
                        AGGREGATE_MEMORY=1, WATCHDOG_INTERVAL=0.05, DISK_WATCHDOG_INTERVAL=0.1)
    nodes = [n for n in ast.parse(RUNNER).body if isinstance(n, ast.FunctionDef)
             and n.name in ('candidate_processes', monitor)]
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<watchdog>', 'exec'), ns)
    usage = ns['disk_usage']
    ns['disk_usage'] = lambda **kw: usage(roots=(), **kw)
    killed = []
    ns['kill_candidate'] = lambda *args: killed.append(args)
    stopped = threading.Event()
    # Single scan for the non-tripping disk monitor.
    stop = SimpleNamespace(is_set=stopped.is_set, wait=lambda _: stopped.set())
    status = dict(supervisor_error=False)
    ns[monitor](123, stop, status)
    assert not status['supervisor_error']
    assert scanned == ['/proc/1/status', '/proc/2/status']
    if monitor == 'memory_watchdog':
        assert status['memory_exceeded']
        assert killed == [(123, [(2, 1024**2)])]
    else:
        assert not killed


@pytest.mark.parametrize('error', [PermissionError, FileNotFoundError, ProcessLookupError])
@pytest.mark.parametrize('site', ['descriptor', 'fd_directory', 'tree_entry', 'tree_directory'])
def test_disk_scan_skips_one_inaccessible_entry(error, site, tmp_path):
    from contextlib import nullcontext
    from types import SimpleNamespace
    import stat
    paths = []
    info = SimpleNamespace(st_mode=stat.S_IFREG, st_dev=1, st_ino=2, st_blocks=16)

    def entry_stat(bad=False):
        if bad:
            raise error()
        return info

    def scandir(path):
        paths.append(path)
        if path == '/proc/1/fd' and site == 'fd_directory':
            raise error()
        if isinstance(path, int):
            if site == 'tree_directory':
                raise error()
            return nullcontext(iter([
                SimpleNamespace(stat=lambda **kw: entry_stat(True)),
                SimpleNamespace(stat=lambda **kw: entry_stat())]))
        return nullcontext(iter([SimpleNamespace(path=path + '/bad'),
                                 SimpleNamespace(path=path + '/good')]))

    def proc_stat(path):
        if path.endswith('/bad'):
            raise error()
        return info

    fake_os = SimpleNamespace(**{name: getattr(os, name) for name in
        ('open', 'close', 'O_RDONLY', 'O_DIRECTORY', 'O_NOFOLLOW')},
        scandir=scandir, stat=proc_stat)
    ns = disk_namespace(os=fake_os, candidate_processes=lambda: [(1, 0), (2, 0)])
    assert ns['disk_usage']([tmp_path] if site.startswith('tree') else []) == 8192
    assert '/proc/2/fd' in paths


@pytest.mark.parametrize('monitor', ['memory_watchdog', 'disk_watchdog'])
def test_watchdogs_fail_closed_when_proc_cannot_be_enumerated(monitor):
    from types import SimpleNamespace
    def listdir(path):
        assert path == '/proc'
        raise PermissionError('cannot enumerate proc')
    ns = disk_namespace(os=SimpleNamespace(listdir=listdir))
    nodes = [n for n in ast.parse(RUNNER).body if isinstance(n, ast.FunctionDef)
             and n.name in ('candidate_processes', monitor)]
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<watchdog>', 'exec'), ns)
    usage = ns['disk_usage']
    ns['disk_usage'] = lambda **kw: usage(roots=(), **kw)
    killed = []
    ns['kill_candidate'] = killed.append
    status = dict(supervisor_error=False)
    ns[monitor](123, threading.Event(), status)
    assert status['supervisor_error']
    assert killed == [123]
