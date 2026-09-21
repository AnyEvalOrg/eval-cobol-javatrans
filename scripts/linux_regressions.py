#!/usr/bin/env python3
"""Run as root ONLY in a disposable reference image with unused UID 65532.

No Inspect installation is needed: import the exact stdlib protocol modules by
path, avoiding the package's Inspect entry point. Never print candidate output,
keys, subprocess stderr, or exception text, even on a regression failure.
"""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'cobol_javatrans'))
from sandbox_runner import SETUP, RUNNER, CLEANUP_COMMAND, QUIESCENCE_COMMAND, QUIESCENCE_CHECK_COMMAND, DIRECTORY_CLEANUP_COMMAND
from receipt import verify_receipt, receipt_failure

FLAGS = ('disk_exceeded', 'memory_exceeded', 'timeout', 'overflow', 'cleanup_failed', 'supervisor_error', 'output_not_decodable')
PYTHON = '/usr/local/bin/python3'
# Only our authored assertion labels may be published, never arbitrary exc.args.
ASSERTION_LABELS = frozenset({
    'cleanup-kill', 'cleanup-quiescent', 'quiescent-before-setup', 'setup-success',
    'authenticated-receipt', 'receipt-cwd', 'failure-classified', 'failure-stage',
    'failure-returncode', 'failure-flags', 'invalid-bytes-detected', 'fork-count',
    'memory-started', 'memory-returncode', 'compile-completed', 'compiler-success',
    'root-linux', 'docker-image-required', 'docker-info', 'docker-child-success',
    'docker-child-stage', 'docker-child-incorrect', 'docker-child-budget',
    'docker-child-returncode', 'cleanup-directory', 'aggregate-memory', 'disk-limit',
    'receipt-deadline', 'pod-usable', 'shm-read-only', 'ptrace-denied',
})


@contextmanager
def check(step):
    try:
        yield
    except Exception as exc:
        summary = dict(stage='regression', step=step, error=type(exc).__name__,
                       returncode=1, flags={'regression_failed': True})
        if (isinstance(exc, AssertionError) and len(exc.args) == 1
                and type(exc.args[0]) is str and exc.args[0] in ASSERTION_LABELS):
            summary['label'] = exc.args[0]
        print(json.dumps(summary), flush=True)
        # Also prevents an enclosing check from publishing a duplicate failure.
        raise SystemExit(1) from None


INVALID_BYTES = "import os; os.write(1, bytes([255])); raise SystemExit(1)"
FORK_EXHAUSTION = '''import errno, os, time
count = 0
while True:
    try:
        pid = os.fork()
    except OSError as exc:
        assert exc.errno == errno.EAGAIN and count > 0
        break
    if pid == 0:
        os.setsid()
        while True: time.sleep(60)
    count += 1
print(count, flush=True)
raise SystemExit(1)
'''
MEMORY_EXHAUSTION = '''import resource
assert resource.getrlimit(resource.RLIMIT_AS)[0] <= 1024**3
assert resource.getrlimit(resource.RLIMIT_DATA)[0] <= 1024**3
assert open('/proc/self/oom_score_adj').read().strip() == '1000'
print('allocating', flush=True)
blocks = []
while True:
    blocks.append(bytearray(8 * 1024**2))
'''


AGGREGATE_MEMORY = """import os, time
for _ in range(3):
    if os.fork() == 0:
        os.setsid()
        blocks = []
        for _ in range(600):
            blocks.append(bytearray(1024**2))
            time.sleep(0.001)
        time.sleep(60)
time.sleep(60)
"""
DISK_EXHAUSTION = """import itertools, os, tempfile
# Keep work below the budget: only a scan of ALL /tmp can catch the sibling.
# The cleanup exec owns deletion of both cjt-* trees after the signed verdict.
other = tempfile.mkdtemp(prefix='cjt-disk-', dir='/tmp')
block = b'x' * 1024**2
for i in itertools.count():
    if i < 64:
        with open(str(i), 'wb') as f:
            f.write(block)
    with open(os.path.join(other, str(i)), 'wb') as f:
        f.write(block)
"""


def retained_files(memfd=False):
    # 300 one-MiB files total; 75 descriptors per worker stays below NOFILE=256.
    create = ("fd = os.memfd_create('retained')" if memfd else
              "path = os.path.join(other, str(i)); fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600); os.unlink(path)")
    return f"""import os, tempfile, time
block = b'x' * 1024**2
for worker in range(4):
    if os.fork() == 0:
        os.setsid()
        other = tempfile.mkdtemp(prefix='cjt-retained-', dir='/tmp')
        descriptors = []
        for i in range(75):
            {create}
            descriptors.append(fd)
            remaining = block
            while remaining:
                remaining = remaining[os.write(fd, remaining):]
            time.sleep(0.005)
        time.sleep(60)
        os._exit(0)
time.sleep(60)
"""


UNLINKED_FILES = retained_files()
MEMFD_FILES = retained_files(memfd=True)
EMPTY_FILES = """import time
for i in range(50000):
    open(str(i), 'w').close()
time.sleep(60)
"""
# Verify PermissionError specifically, not an unrelated nonzero exit. Also
# check the actual supervisor: PID 1 may be the container init/sleep process.
PTRACE_DENIED = """import os
for path in ('/proc/1/fd/0', f'/proc/{os.getppid()}/fd/0'):
    try:
        os.stat(path)
    except PermissionError:
        continue
    else:
        raise SystemExit(0)
print('ptrace denied')
raise SystemExit(1)
"""
SHM_WRITE = "open('/dev/shm/cjt-write', 'wb').write(b'x')"
DISK_CASES = {'disk': DISK_EXHAUSTION, 'unlinked_files': UNLINKED_FILES,
              'memfd_files': MEMFD_FILES, 'empty_files': EMPTY_FILES}
DETACHED_CHILD = """import os, time
if os.fork() == 0:
    os.setsid()
    open('ready', 'w').close()
    time.sleep(60)
    os._exit(0)
while not os.path.exists('ready'):
    time.sleep(0.01)
"""


def invoke(command, *, timeout=50, **kwargs):
    return subprocess.run(command, capture_output=True, text=True, timeout=timeout, **kwargs)


def independent_cleanup():
    result = invoke(CLEANUP_COMMAND)
    assert result.returncode in (0, 1), 'cleanup-kill'
    result = invoke(QUIESCENCE_COMMAND)
    assert result.returncode == 0, 'cleanup-quiescent'
    assert invoke(DIRECTORY_CLEANUP_COMMAND).returncode == 0, 'cleanup-directory'


def execute(request, *, budget=False):
    # pgrep also counts zombies, which both supervisor and independent cleanup
    # deliberately ignore. Check the same live-UID predicate without killing.
    assert invoke(QUIESCENCE_CHECK_COMMAND).returncode == 0, 'quiescent-before-setup'
    setup = invoke(['timeout', '-s', 'KILL', '5s', PYTHON, '-I', '-c', SETUP],
                   input=json.dumps(request))
    assert setup.returncode == 0, 'setup-success'
    setup = json.loads(setup.stdout)
    try:
        command = ['timeout', '-s', 'KILL', '40s', PYTHON, '-I', '-c', RUNNER, setup['cwd']]
        if budget:
            # A real inherited address-space/data budget, not a stub. This tests
            # limit clamping and MemoryError; unlike Docker it cannot attest OOM.
            command = ['prlimit', '--as=536870912:536870912',
                       '--data=536870912:536870912', '--'] + command
        started = time.monotonic()
        result = invoke(command)
        assert time.monotonic() - started < 40, 'receipt-deadline'
        receipt = verify_receipt(result.stdout, bytes.fromhex(setup['key']))
        assert receipt is not None, 'authenticated-receipt'
        assert receipt['cwd'] == setup['cwd'], 'receipt-cwd'
        return receipt
    finally:
        independent_cleanup()
        assert invoke(QUIESCENCE_CHECK_COMMAND).returncode == 0, 'pod-usable'


def request_for(code):
    return dict(files={}, argv=[PYTHON, '-I', '-c', 'pass'],
                run_argv=[PYTHON, '-I', '-c', code],
                timeout=10, run_timeout=15, output_limit=1024**2)


def report(receipt, **flags):
    print(json.dumps(dict(stage=receipt['stage'], returncode=receipt['returncode'],
                         flags={**{key: receipt.get(key, False) for key in FLAGS}, **flags})), flush=True)


def check_failure(code, *, budget=False, **flags):
    receipt = execute(request_for(code), budget=budget)
    # The same failure classifier used by translation_scorer, where any reason
    # produces Inspect's INCORRECT verdict before answer comparison in BOTH tasks.
    assert receipt_failure(receipt) is not None, 'failure-classified'
    assert receipt['stage'] == 'run', 'failure-stage'
    assert receipt['returncode'] in (1, -9), 'failure-returncode'
    assert not any(receipt.get(key) for key in ('timeout', 'overflow', 'cleanup_failed', 'supervisor_error')), 'failure-flags'
    if code == INVALID_BYTES:
        assert receipt['output_not_decodable'], 'invalid-bytes-detected'
    elif code == PTRACE_DENIED:
        assert receipt['returncode'] == 1 and receipt['output'] == 'ptrace denied\n', 'ptrace-denied'
        assert not any(receipt.get(k) for k in FLAGS), 'failure-flags'
    elif code == FORK_EXHAUSTION:
        assert receipt.get('memory_exceeded') or (receipt['returncode'] == 1 and
            0 < int(receipt['output'].strip()) < 64), 'fork-count'
    elif code == MEMORY_EXHAUSTION:
        assert receipt['output'] == 'allocating\n', 'memory-started'
        assert receipt['returncode'] == (1 if budget else -9), 'memory-returncode'
    report(receipt, incorrect=True, **flags)


def compiler_smokes():
    # Exercise actual javac AND java with the supervisor's 64-thread / 8 GiB
    # virtual-space limits and JAVA_TOOL_OPTIONS, plus native cobc/executable.
    for step, files, compile_argv, run_argv in (
        ('compiler_smoke:javac', {'Main.java': 'public class Main { public static void main(String[] a) {} }'},
         ['javac', 'Main.java'], ['java', '-cp', '.', 'Main']),
        ('compiler_smoke:cobc', {'smoke.cbl': '       identification division.\n       program-id. smoke.\n'
                      '       procedure division.\n           stop run.\n'},
         ['cobc', '-x', '-o', 'smoke', 'smoke.cbl'], ['./smoke']),
    ):
        with check(step):
            request = dict(files=files, argv=compile_argv, run_argv=run_argv,
                           timeout=15, run_timeout=10, output_limit=1024**2)
            receipt = execute(request)
            # A compile-only receipt is valid protocol, but cannot pass this
            # smoke: both requests explicitly ask the supervisor to run too.
            assert receipt['stage'] == 'run', 'compile-completed'
            assert receipt_failure(receipt) is None, 'compiler-success'
            report(receipt, compiler_startup=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', help='Exact reference image tag/digest for nested Docker memory regression')
    parser.add_argument('--docker-cli', help='Docker client path (Cloud Build supplies its client via /workspace)')
    parser.add_argument('--memory-child', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    assert sys.platform == 'linux' and os.geteuid() == 0, 'root-linux'
    if args.memory_child:
        with check('memory:docker-child'):
            receipt = execute(request_for(AGGREGATE_MEMORY))
            assert receipt.get('memory_exceeded') and receipt_failure(receipt), 'aggregate-memory'
            report(receipt, incorrect=True, docker_memory_budget=True,
                   pod_usable=True, receipt_within_deadline=True)
        for name, code in DISK_CASES.items():
            with check(name + ':docker-child'):
                receipt = execute(request_for(code))
                assert receipt.get('disk_exceeded') and receipt['returncode'] != 0, 'disk-limit'
                assert receipt['stage'] == 'run', 'failure-stage'
                assert receipt_failure(receipt) == 'disk limit exceeded', 'failure-classified'
                assert not any(receipt.get(k) for k in FLAGS if k != 'disk_exceeded'), 'failure-flags'
                report(receipt, incorrect=True, pod_usable=True, receipt_within_deadline=True)
        with check('shm_write:docker-child'):
            receipt = execute(request_for(SHM_WRITE))
            assert receipt['stage'] == 'run' and receipt['returncode'] == 1, 'shm-read-only'
            assert not any(receipt.get(k) for k in FLAGS), 'failure-flags'
            report(receipt, incorrect=True, pod_usable=True, receipt_within_deadline=True)
        with check('ptrace_denied:docker-child'):
            check_failure(PTRACE_DENIED, pod_usable=True, receipt_within_deadline=True)
        return
    compiler_smokes()
    with check('ptrace_denied'):
        check_failure(PTRACE_DENIED)
    with check('invalid_bytes'):
        check_failure(INVALID_BYTES, invalid_bytes=True)
    with check('fork_exhaustion'):
        check_failure(FORK_EXHAUSTION, fork_exhaustion=True)
    docker = args.docker_cli or shutil.which('docker')
    if docker:
        with check('memory:docker'):
            docker_memory_check(docker, args.image)
    else:
        with check('memory:prlimit'):
            check_failure(MEMORY_EXHAUSTION, budget=True, prlimit_memory_budget=True)


def docker_memory_check(docker, image):
    assert image, 'docker-image-required'
    # Do not silently replace a broken Docker test with the weaker fallback.
    assert invoke([docker, 'info']).returncode == 0, 'docker-info'
    # The checkout must exist at this same path on the Docker daemon host.
    # Cloud Build provides /workspace to both the outer and nested containers.
    # Anonymous disk volume permits compiler execution; --rm (or rm -v on
    # failure) removes it. The supervisor's disk watchdog bounds writes.
    name = f'cjt-memory-regression-{os.getpid()}'
    try:
        result = invoke([
            docker, 'run', '--rm', '--init', '--name', name, '--network=none',
            '--memory=2g', '--memory-swap=2g', '--pids-limit=128', '--cpus=1',
            '--read-only', '--volume', '/tmp', '--tmpfs', '/dev/shm:ro,size=16m',
            '--cap-drop=ALL', '--cap-add=SETUID', '--cap-add=SETGID', '--cap-add=KILL',
            '--cap-add=CHOWN', '--cap-add=DAC_OVERRIDE', '--cap-add=SYS_PTRACE', '--security-opt=no-new-privileges',
            '--user=0:0', '-v', f'{ROOT}:{ROOT}:ro', '--entrypoint', PYTHON,
            image, str(Path(__file__).resolve()), '--memory-child',
        ], timeout=300)
        assert result.returncode == 0, 'docker-child-success'
        # Parse and whitelist the child's summary; never forward raw stdout.
        summaries = [json.loads(line) for line in result.stdout.splitlines()]
        assert len(summaries) == 3 + len(DISK_CASES), 'docker-child-success'
        for summary, expected in zip(summaries, ('memory_exceeded',) + ('disk_exceeded',) * len(DISK_CASES) + (None, None)):
            assert summary['stage'] == 'run', 'docker-child-stage'
            assert summary['flags']['incorrect'] is True, 'docker-child-incorrect'
            if expected:
                assert summary['flags'][expected] is True, 'docker-child-budget'
            else:
                assert not any(summary['flags'].get(k) for k in FLAGS), 'failure-flags'
            assert summary['returncode'] != 0, 'docker-child-returncode'
            report({**summary, **summary['flags']}, incorrect=True,
                   pod_usable=summary['flags'].get('pod_usable', False),
                   receipt_within_deadline=summary['flags'].get('receipt_within_deadline', False))

    finally:
        invoke([docker, 'rm', '-f', '-v', name])


if __name__ == '__main__':
    with check('startup'):
        main()
