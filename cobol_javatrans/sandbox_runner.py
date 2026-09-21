"""Trusted supervisor source, executed ONLY in the external Linux sandbox.

A completed setup exec writes the request into a fresh directory. The supervisor
reads and unlinks it before starting the candidate. The setup Python process
generates the key locally; no ancestor shell receives it as stdin or an argument. The key is then memory-only.
The root supervisor drops the child to reserved UID/GID 65532 before exec.
PR_SET_DUMPABLE also protects supervisor memory/fds.
The child has separate stdio, no inherited supervisor descriptors, no core dumps,
no privilege gains, and a bounded process limit (compiler subprocesses and JVM threads are required).
Only the supervisor can authenticate the wait() status. Provider stdout markers
can truncate/destroy the receipt, but cannot manufacture a valid passing receipt.
"""

CANDIDATE_UID = 65532
CANDIDATE_GID = 65532
# procps pkill returns 1 when there are no matching processes.
CLEANUP_COMMAND = ["timeout", "-s", "KILL", "5s",
                   "/usr/bin/pkill", "-KILL", "-u", str(CANDIDATE_UID)]

# Compilers need forks and JVMs need threads. After the template's independent
# pkill exec, verify quiescence with repeated UID sweeps (escaped sessions too).
# Ignore zombies: they cannot execute and belong to the container's reaper.
UID_QUIESCENCE = r'''
import os, subprocess, sys, time
check_only = "--check-only" in sys.argv[1:]
until = time.monotonic() + 3
while True:
    if not check_only:
        sweep = subprocess.run(["/usr/bin/pkill", "-KILL", "-u", "65532"],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=1)
        if sweep.returncode not in (0, 1):
            raise SystemExit(2)
    active = False
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open("/proc/" + name + "/status") as stream:
                status = dict(line.split(":", 1) for line in stream if ":" in line)
            if status["Uid"].split()[0] == "65532" and status["State"].split()[0] not in {"Z", "X"}:
                active = True
        except FileNotFoundError:
            pass
    if not active:
        break
    if check_only or time.monotonic() >= until:
        raise SystemExit(2)
    time.sleep(0.02)
'''
QUIESCENCE_COMMAND = ["timeout", "-s", "KILL", "5s",
                      "/usr/local/bin/python3", "-I", "-c", UID_QUIESCENCE]
# Only the independent exec deletes candidate directories. timeout bounds even
# uninterruptible filesystem work; the receipt-producing process never deletes.
DIRECTORY_CLEANUP_COMMAND = [
    "timeout", "-s", "KILL", "5s", "find", "/tmp", "-maxdepth", "1",
    "-name", "cjt-*", "-exec", "rm", "-rf", "--", "{}", "+",
]
# Same definition of live processes, without killing an unexpectedly occupied UID.
QUIESCENCE_CHECK_COMMAND = QUIESCENCE_COMMAND + ["--check-only"]

# Setup runs before any candidate exists. Both execs are bounded by the scorer.
SETUP = r'''
import json, os, secrets, sys, tempfile
request = json.load(sys.stdin)
key = secrets.token_hex(32)
request["key"] = key
work = tempfile.mkdtemp(prefix="cjt-", dir="/tmp")
with open(os.path.join(work, "request.json"), "x", encoding="utf-8") as f:
    json.dump(request, f)
sys.stdout.write(json.dumps({"cwd": work, "key": key}))
'''

# Kept as source: importing this module never starts a process or executes code.
RUNNER = r'''
import base64
import ctypes
import errno
import hashlib
import hmac
import json
import os
import resource
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time

CANDIDATE_UID = 65532
CANDIDATE_GID = 65532
libc = ctypes.CDLL(None, use_errno=True)
if os.getuid() != 0 or libc.prctl(4, 0, 0, 0, 0) != 0:
    raise RuntimeError("root Linux supervisor with protected memory required")
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
    raise RuntimeError("subreaper required")
work = sys.argv[1]
request_path = os.path.join(work, "request.json")
with open(request_path, encoding="utf-8") as f:
    request = json.load(f)
os.unlink(request_path)
key = bytes.fromhex(request.pop("key"))
limit = request["output_limit"]


JAVA_TOOL_OPTIONS = "-Xmx512m -XX:MaxMetaspaceSize=256m -XX:ReservedCodeCacheSize=64m -Xss1m"


def candidate_limits(java=False):
    # Leave process slots for the root supervisor and independent cleanup execs.
    # Clamp to inherited budgets as well (the Linux regression uses prlimit).
    # The RSS watchdog bounds aggregate memory, including Java reservations
    # that become resident. Keep independent per-process native limits too.
    memory = 8 * 1024**3 if java else 1024**3
    for kind, value in ((resource.RLIMIT_NPROC, 64),
                        (resource.RLIMIT_AS, memory),
                        (resource.RLIMIT_DATA, memory),
                        (resource.RLIMIT_FSIZE, limit),
                        (resource.RLIMIT_CORE, 0)):
        hard = resource.getrlimit(kind)[1]
        if hard != resource.RLIM_INFINITY:
            value = min(value, hard)
        resource.setrlimit(kind, (value, value))


def restrict_child(java=False):
    # Still root in the supervisor's preexec child: set this BEFORE exec/drop so
    # even immediate allocations and all descendants inherit the OOM preference.
    with open("/proc/self/oom_score_adj", "w") as f:
        f.write("1000")
    # No parent-death signal is trusted: the scorer independently kills this UID.
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        os._exit(125)
    if libc.prctl(8, 0, 0, 0, 0) != 0:  # PR_SET_KEEPCAPS = 0
        os._exit(125)
    os.setgroups([])
    os.setresgid(CANDIDATE_GID, CANDIDATE_GID, CANDIDATE_GID)
    os.setresuid(CANDIDATE_UID, CANDIDATE_UID, CANDIDATE_UID)
    # Set NPROC AFTER changing UID, avoiding execve's PF_NPROC_EXCEEDED trap.
    # These hard limits and the irreversible credential drop survive exec.
    candidate_limits(java)


def kill_group(pgid):
    # Kill the entire original session's process group, even if the leader exited.
    # An independent UID sweep below also kills descendants that change sessions.
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(pgid, sig)
        except ProcessLookupError:
            pass
        if sig == signal.SIGTERM:
            time.sleep(0.1)



AGGREGATE_MEMORY = 768 * 1024**2
WATCHDOG_INTERVAL = 0.05
AGGREGATE_DISK = 256 * 1024**2
DISK_WATCHDOG_INTERVAL = 0.1


def candidate_processes():
    # gVisor reports full per-process VmRSS even for forked copy-on-write pages:
    # 64 Python forks can hit this conservative aggregate budget. Legitimate
    # compiler/JVM chains use a handful of processes and stay far below 768 MiB.
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open("/proc/" + name + "/status") as f:
                status = dict(line.split(":", 1) for line in f if ":" in line)
            if status["Uid"].split()[0] == str(CANDIDATE_UID):
                yield int(name), int(status.get("VmRSS", "0 kB").split()[0]) * 1024
        except (FileNotFoundError, ProcessLookupError):
            pass


def kill_candidate(pgid, processes=None):
    # Shared watchdog path: immediate KILL without a TERM grace-period burst.
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    if processes is None:
        processes = candidate_processes()
    for pid, _ in processes:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def memory_watchdog(pgid, stopped, status):
    try:
        while not stopped.is_set():
            processes = list(candidate_processes())
            if sum(rss for _, rss in processes) > AGGREGATE_MEMORY:
                status["memory_exceeded"] = True
                kill_candidate(pgid, processes)
                return
            stopped.wait(WATCHDOG_INTERVAL)
    except Exception:
        status["supervisor_error"] = True
        # Fail closed if monitoring itself fails; don't run unmonitored.
        kill_candidate(pgid)


def disk_usage(roots=("/tmp", "/dev/shm")):
    # Use directory descriptors so a concurrent rename/symlink replacement
    # cannot redirect traversal outside the mounts. Never open candidate file
    # contents or FIFOs/devices; count allocated blocks, not apparent size.
    races = (errno.ENOENT, errno.ENOTDIR, errno.ELOOP)

    def walk(path, parent=None):
        try:
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                         dir_fd=parent)
        except OSError as exc:
            if exc.errno in races:
                return 0
            raise
        try:
            total = 0
            with os.scandir(fd) as entries:
                for entry in entries:
                    try:
                        info = entry.stat(follow_symlinks=False)
                        if stat.S_ISREG(info.st_mode):
                            total += info.st_blocks * 512
                        elif stat.S_ISDIR(info.st_mode):
                            total += walk(entry.name, fd)
                    except OSError as exc:
                        if exc.errno not in races:
                            raise
            return total
        finally:
            os.close(fd)

    return sum(walk(root) for root in roots)


def disk_watchdog(pgid, stopped, status):
    try:
        while not stopped.is_set():
            if disk_usage() > AGGREGATE_DISK:
                status["disk_exceeded"] = True
                kill_candidate(pgid)
                return
            stopped.wait(DISK_WATCHDOG_INTERVAL)
    except Exception:
        status["supervisor_error"] = True
        kill_candidate(pgid)


def sweep_uid():
    # NPROC must permit compiler subprocesses/JVM threads. Repeatedly sweep the
    # reserved UID and reap adopted descendants, including setsid escapees.
    until = time.monotonic() + 3
    while True:
        active = False
        for name in os.listdir("/proc"):
            if not name.isdigit():
                continue
            try:
                with open("/proc/" + name + "/status") as f:
                    status = dict(line.split(":", 1) for line in f if ":" in line)
                if (status["Uid"].split()[0] == str(CANDIDATE_UID)
                        and status["State"].split()[0] not in {"Z", "X"}):
                    active = True
                    os.kill(int(name), signal.SIGKILL)
            except ProcessLookupError:
                pass
            except FileNotFoundError:
                pass
        while True:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            if pid == 0:
                break
        if not active:
            return
        if time.monotonic() >= until:
            raise RuntimeError("UID sweep did not complete")
        time.sleep(0.02)


def run_step(argv, timeout, candidate_work):
    if not isinstance(argv, list) or not argv or any(not isinstance(x, str) for x in argv):
        raise ValueError("argv must be a nonempty string list")
    status = dict(returncode=125, timeout=False, overflow=False,
                  cleanup_failed=False, supervisor_error=False, memory_exceeded=False, disk_exceeded=False)
    output = b""
    child = None
    watchers = []
    stopped = threading.Event()
    java = os.path.basename(argv[0]) in {"javac", "java"}
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": candidate_work, "TMPDIR": candidate_work}
    if java:
        env["JAVA_TOOL_OPTIONS"] = JAVA_TOOL_OPTIONS
    try:
        with tempfile.TemporaryFile(dir=work) as stdout, tempfile.TemporaryFile(dir=work) as stderr:
            try:
                child = subprocess.Popen(
                    argv, cwd=candidate_work, env=env,
                    stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, close_fds=True,
                    start_new_session=True, preexec_fn=lambda: restrict_child(java),
                )
                # Start only after Popen's preexec has completed (no fork with
                # this watchdog thread active). Keep monitoring through cleanup.
                for monitor in (memory_watchdog, disk_watchdog):
                    watcher = threading.Thread(target=monitor,
                        args=(child.pid, stopped, status), daemon=True)
                    watcher.start()
                    watchers.append(watcher)
                try:
                    status["returncode"] = child.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    status["timeout"] = True
            finally:
                # No cleanup subprocesses: an exhausted PID budget cannot prevent
                # signing. Independently guard EVERY step so later failures still
                # yield a receipt, and never run the next stage after failed cleanup.
                if child is not None:
                    try:
                        kill_group(child.pid)
                    except Exception:
                        status["cleanup_failed"] = True
                    try:
                        status["returncode"] = child.wait(timeout=1)
                    except Exception:
                        status["cleanup_failed"] = True
                    try:
                        sweep_uid()
                    except Exception:
                        status["cleanup_failed"] = True
                stopped.set()
                for watcher in watchers:
                    watcher.join()
            stdout.seek(0)
            output = stdout.read(limit + 1)
            status["overflow"] = len(output) >= limit or os.fstat(stderr.fileno()).st_size >= limit
    except Exception:
        status["supervisor_error"] = True
    return status, output


status = dict(returncode=125, timeout=False, overflow=False,
              cleanup_failed=False, supervisor_error=False, memory_exceeded=False, disk_exceeded=False)
stage = "compile"
output = b""

try:
    # Keep launch/request directory root-owned; only its child is writable.
    candidate_work = os.path.join(work, "candidate")
    os.mkdir(candidate_work, 0o700)
    os.chown(candidate_work, CANDIDATE_UID, CANDIDATE_GID)
    os.chmod(work, 0o711)
    for name, content in request["files"].items():
        if not name or name in {".", ".."} or os.path.basename(name) != name:
            raise ValueError("Only plain filenames are allowed")
        path = os.path.join(candidate_work, name)
        with open(path, "x", encoding="utf-8") as f:
            f.write(content)
        os.chmod(path, 0o644)
    status, output = run_step(request["argv"], request["timeout"], candidate_work)
    if (status["returncode"] == 0 and not any(status[flag] for flag in
            ("timeout", "overflow", "cleanup_failed", "supervisor_error", "memory_exceeded", "disk_exceeded")) and "run_argv" in request):
        stage = "run"
        status, output = run_step(request["run_argv"], request["run_timeout"], candidate_work)
        if "output_file" in request and status["returncode"] == 0 and not status["timeout"]:
            name = request["output_file"]
            if not name or name in {".", ".."} or os.path.basename(name) != name:
                raise ValueError("Invalid output filename")
            # Candidate-controlled symlinks/FIFOs/devices must never be read as root.
            try:
                fd = os.open(os.path.join(candidate_work, name), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, "rb") as f:
                    info = os.fstat(f.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_uid != CANDIDATE_UID or info.st_nlink != 1:
                        raise ValueError("Unsafe output file")
                    output = f.read(limit + 1)
                    status["overflow"] = status["overflow"] or len(output) >= limit
            except (OSError, ValueError):
                status["returncode"] = 125
                output = b""
except Exception:
    # Candidate filesystem changes and post-wait failures must not lose a receipt.
    status["supervisor_error"] = True
finally:
    body = json.dumps({**status, "stage": stage,
                      "output": base64.b64encode(output).decode("ascii"), "cwd": work}, separators=(",", ":"))
    tag = hmac.new(key, body.encode(), hashlib.sha256).hexdigest()
    sys.stdout.write(json.dumps({"body": body, "tag": tag}))
    sys.stdout.flush()
    os._exit(0)  # No deletion, finalizers, or interpreter shutdown after signing.
'''
