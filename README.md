# COBOL-JavaTrans for AnyEval

`eval-cobol-javatrans` 1.0.0 packages two offline Inspect tasks:

| Task reference | Samples | Score |
| --- | ---: | --- |
| `cobol_javatrans/cobol_to_java` | 143 | Java test Main exits successfully |
| `cobol_javatrans/java_to_cobol` | 143 | Every upstream COBOL caller passes |

Each task uses one generation and one epoch. Accuracy is **pass@1**. There is no
model judge, model tool access, or test feedback. The 286 task samples share 143
original upstream `task_id` values, such as `HumanEval/0`; IDs are never renumbered.

## Frozen source and offline data

Source: [COBOL-Coder/COBOL-Coder](https://github.com/COBOL-Coder/COBOL-Coder), commit
`2b14b7bf7e55556205654c6f7657fa60e36251fa`,
`evaluation/data/COBOL-JavaTrans.jsonl`. All 143 records and all **807 COBOL caller
tests** are retained, with one Java test program per record. Apache-2.0 attribution
and upstream license text are in `NOTICE.md`, `UPSTREAM-LICENSE`, and `LICENSE`.

The wheel includes `cobol_javatrans/data/problems.jsonl.gz` and `manifest.json`.
The manifest records the exact ID list and SHA-256 checksums of the original JSONL,
compressed artifact, and ID sequence. Loading uses `importlib.resources`, validates
the artifact hash and IDs, and requires no checkout, network, or dataset cache.
`python scripts/build_dataset.py` regenerates these files deterministically from
the provided root `COBOL-JavaTrans.jsonl`, without downloading anything.

## Prompt and grading protocol

COBOL-to-Java input contains `COBOL_canonical_solution` as the **source program**
and `Java_prompt` as the target skeleton. The instruction requires class `Solution`
and the exact Java method signature from that skeleton, including its method name.
Java-to-COBOL input contains `Java_canonical_solution` as the **source program** and
`COBOL_prompt` as the target skeleton. The model must preserve PROGRAM-ID and LINKAGE
layouts, complete WORKING-STORAGE and PROCEDURE DIVISION USING LINKED-ITEMS, write
RESULT, and end the complete program with END PROGRAM. Original examples already
inside either required skeleton remain visible.

The requested answer is exactly one closed, nonempty fenced `java` or `cobol` block.
The scorer extracts that language block and rejects missing or multiple matching
blocks. The source-language canonical program is intentional translation input;
the **target-language canonical solution**, structured tests, and expected results
are never included in input or sample metadata. Metadata contains only `task_id`
and `entry_point`, and targets are empty. Private records live in the scorer closure.

For Java, the scorer writes cleaned `Solution.java` and `Main.java`, the latter
exactly `"import java.util.*;\n" + Java_tests`. The supervisor invokes the argv list
`["javac", "Solution.java", "Main.java"]`, then `["java", "-cp", ".", "Main"]`.
Upstream Main throws AssertionError on failure; assertions are not enabled with
`-ea` because the tests use explicit throws. Compilation must succeed and the
actual runtime exit status must be zero. Stdout is not used to decide correctness.

For each COBOL test, the scorer starts a fresh directory containing `call.cbl` and
`solution.cbl`, invokes `["cobc", "-w", "-fformat=variable", "-x", "call.cbl",
"solution.cbl"]`, then `["./call"]`. It reads the output file named
`entry_point.upper().replace("_", "-") + ".TXT"`. A missing/unsafe output file,
compile error, runtime error, timeout, overflow, undecodable output, or wrong result
is incorrect.
All callers must pass; the scorer stops at the first failure.

The upstream `parse` and `is_equal` functions are copied faithfully:

- Bool is true only when the stripped first line equals `1`.
- Int and Float accept upstream `p` and `y` prefixes as negative signs.
- String strips surrounding whitespace from the first line.
- Lists parse all lines, then truncate to the expected length; surplus malformed
  lines still fail. Only List[Int], List[Float], and List[String] are supported.
- Floats use `math.isclose` with `abs_tol=0.001` and its default relative tolerance.
  List[Float] compares zipped pairs without a length check, including upstream's
  acceptance of some short lists. Other values use Python equality.
- The result file must contain at least one line. Expected tuples become lists.

Expected values are read with `ast.literal_eval`, replacing upstream's `eval`;
all 807 frozen expected values are literals. Expected COBOL outputs remain on the
host. Java assertions and their expected values necessarily enter the private
sandbox as Main.java, as in the upstream harness.

## Trusted sandbox protocol

No model code runs in the host scorer. Requests contain a filename-to-content
`files` mapping, shell-free `argv`, `timeout`, and `output_limit`; a compile/run pair
also carries `run_argv`, `run_timeout`, and optionally `output_file`. Both steps
execute in the same fresh candidate directory under one trusted root supervisor,
with **60 seconds for compilation and 30 seconds for execution**. Every COBOL
caller gets its own pair and directory. There is no candidate-controlled Python
driver or printed pass marker.

The template's setup exec creates an unpredictable `/tmp/cjt-*` directory and
locally generates a 256-bit HMAC key. The root supervisor reads and unlinks the
request before launching children. Only `candidate/` is UID-owned; its parent is
root-owned. Supervisor memory/file descriptors are protected by `PR_SET_DUMPABLE=0`.
Each compiler/runtime child clears supplementary groups, irreversibly drops real,
effective, and saved UID/GID to **65532**, sets `no_new_privs`, retains no
capabilities, disables core dumps, and runs in a new session with closed inherited
file descriptors. Both launches use argv lists, never `bash -c` or `shell=True`.

**Required change from the Python template:** its `RLIMIT_NPROC=0` would prevent
GnuCOBOL from invoking the C toolchain and the JVM from creating threads. Here the
hard process/thread limit is **64**, below the container's 128 PID slots, leaving
room for the supervisor and independent cleanup. Each step ends with TERM/KILL of
its process group and repeated reserved-UID sweeps using `/proc` and `os.kill`,
without spawning cleanup processes. The supervisor acts as a Linux subreaper and
reaps adopted descendants, including those that changed sessions. Post-run errors
produce signed failure flags, and failed cleanup blocks the next stage. The receipt
is written and flushed, then the supervisor immediately calls `os._exit(0)`.
No directory deletion or interpreter finalizers run in that exec.

Native compiler/runtime children have hard **1 GiB RLIMIT_AS and RLIMIT_DATA**
limits. Java steps use **8 GiB** virtual address/data limits to accommodate JVM
reservations and `JAVA_TOOL_OPTIONS="-Xmx512m -XX:MaxMetaspaceSize=256m
-XX:ReservedCodeCacheSize=64m -Xss1m"`. These limits are clamped to any tighter
inherited hard limits. The root preexec child writes `1000` to its
`/proc/self/oom_score_adj` before dropping credentials; descendants inherit the
OOM preference on native Linux; gVisor records this setting but does not use it.
It is not the aggregate memory boundary. A supervisor watchdog runs throughout
each candidate step, sampling `/proc/<pid>/status` every **50 ms** and summing
`VmRSS` for every process with UID 65532, including detached sessions and JVMs.
Above **768 MiB**, it immediately kills the candidate group and UID processes and
signs `memory_exceeded=True`, which scores INCORRECT (`memory limit exceeded`).
gVisor counts copy-on-write pages in each fork's VmRSS, so fork exhaustion may
legitimately trip this conservative budget. Compiler/JVM chains use a handful of
processes and stay far below 768 MiB. Core dumps remain disabled and RLIMIT_FSIZE
remains 1 MiB per file.

A second supervisor watchdog scans **all of `/tmp` and `/dev/shm` every 100 ms**,
summing `st_blocks * 512` for regular files with a race-tolerant `os.scandir` walk
that does not follow symlinks. Above **256 MiB**, it uses the same immediate kill
path and signs `disk_exceeded=True`, scoring INCORRECT (`disk limit exceeded`).
Both watchdogs remain active through process cleanup; either flag blocks the next
stage. Directory deletion still belongs to the independent cleanup exec.

The host always performs the template's separate bounded
`/usr/bin/pkill -KILL -u 65532` cleanup exec, even after setup failures, lost or
invalid receipts, and cancellation. Because forks are permitted, another bounded
exec repeats sweeps and verifies that no live process with that UID remains before
reusing the sandbox. Zombies cannot execute and are ignored by this independent
verification. A third independent exec deletes `/tmp/cjt-*` using
`timeout -s KILL 5s find ... -exec rm -rf ...`; deletion never delays the receipt.
The scorer decides the signed verdict first. If independent cleanup or deletion
fails, a signed failure retains its INCORRECT explanation; a signed success
becomes INCORRECT with `candidate left processes that could not be cleaned up`.
No further test runs after failed cleanup. Only an absent valid signed receipt
causes the withheld-details harness error, including when cleanup also fails.
Each pod belongs to one sample and is discarded afterwards, with no reuse across
samples. UID 65532 must be reserved solely for candidates; tests execute
sequentially. An unauthenticated run waits through its host deadline before cleanup
to avoid racing a delayed supervisor start.

Setup has a 5-second container/provider limit and 10-second host limit. The combined
supervisor has a 100-second container/provider limit and 105-second host limit,
covering the two step deadlines and cleanup overhead. Each independent cleanup
exec has a 5-second container/provider limit and 10-second host limit. Normal
independent cleanup removes the directory; sandbox teardown discards leftovers
after failed cleanup or an abnormally terminated supervisor.

Stdout/stderr use anonymous bounded files. File size and output limits are 1 MiB.
COBOL output is read only after child cleanup, using O_NOFOLLOW/O_NONBLOCK and
checks for a regular file, reserved UID ownership, and one hard link. Missing
files, symlinks, FIFOs, and unsafe files fail. The receipt authenticates directory,
stage, exit status from wait(), timeout, overflow, aggregate memory exhaustion,
cleanup/supervisor failures, and captured bytes with HMAC-SHA256. Candidate/provider completion markers cannot forge a successful
receipt; provider success/returncode never decide the compile/run verdict.
An absent or unverifiable receipt (including a wrong directory, lost exec response,
or setup/supervisor exec timeout or output limit) is a harness failure: the scorer
raises `RuntimeError("Private sandbox operation failed; details withheld.")`.
Inspect records a sample error and AnyEval refuses to publish the run, so it does
not enter the published pass rate. Candidate failures reported in authenticated
receipts, including timeouts, memory exhaustion, output overflow, post-run/cleanup
failures, and undecodable output, remain incorrect verdicts. Raw candidate bytes are base64
encoded before signing. The verifier authenticates the envelope and strictly
validates supervisor-owned fields first; malformed base64, output shape, or UTF-8
then becomes authenticated `output not decodable`, never a missing receipt.
This also applies to Java stdout even though valid Java stdout is not compared.

`publication.py` preserves the template's private Inspect event proxy and
context-local provider log filtering. Private sandbox calls produce no transcript
events; exceptions are raised outside private frames with `details withheld`.
`redaction.yaml` supplies additional declarative protection. Tests exercise the
pinned Inspect proxy and the local AnyEval exporter when available.

## Docker and Kubernetes

```bash
python -m pip install '.[inspect]'
inspect eval cobol_javatrans/cobol_to_java --model <provider/model> -T sandbox_type=docker
inspect eval cobol_javatrans/java_to_cobol --model <provider/model> -T sandbox_type=docker
```

Compose builds `cobol_javatrans/Dockerfile`, disables network access, and limits the
container to 1 CPU, 2 GiB memory, and 128 processes. The Dockerfile is adapted from
the supplied shared sandbox Dockerfile: that file had OpenJDK 21; this package uses
**OpenJDK 21** as requested, with `python:3.12-slim-trixie` to provide it. It installs
GnuCOBOL, procps, util-linux, and hostname, and reserves UID/GID 65532. Building the
image requires package downloads; evaluation does not.

The default is Kubernetes:

```bash
python -m pip install '.[anyeval]'
inspect eval cobol_javatrans/cobol_to_java --model <provider/model>
```

`values.yaml` uses
`us-central1-docker.pkg.dev/openevalz-sbx-84737/openevalz/eval-cobol-sandbox:1.0.0`.
Publish a matching image and pin its resolved digest in AnyEval's catalog before
running. This package does not build, push, deploy, or attest that registry image.

The packaged chart creates a Pod and native deny-all NetworkPolicy whose selector
is **`app.kubernetes.io/instance: <release>`**, never the entire namespace. Both
ingress and egress, including DNS, are denied. The Pod uses gVisor, GKE Spot, no
service-account token, no host networking/mounts, no sidecars, and restartPolicy
Never. Requests equal limits: **1 CPU, 2 GiB memory, 1 GiB ephemeral storage**.
Equal CPU/memory reservations provide Guaranteed QoS and reserve the supervisor's
memory headroom; `values.yaml` documents the candidate memory budgets. The sandbox
root filesystem is read-only. `/tmp` is a **disk-backed `emptyDir`** with
**512Mi sizeLimit** as an eviction backstop. `/dev/shm` remains a Memory `emptyDir`
with **16Mi sizeLimit**. Production gVisor does not enforce Memory `emptyDir`
sizeLimit as a tmpfs mount size, so containment uses the supervisor's disk
watchdog: **256 MiB + one 100 ms write burst** across both mounts. gVisor gofer
write throughput makes this burst small relative to the 512 MiB backstop and
1 GiB pod ephemeral-storage budget.
Autopilot supplies the Spot toleration; the chart adds none. The task defaults
`INSPECT_K8S_DEFAULT_NAMESPACE` to `anyeval-sandbox` without overriding an existing
setting. Trusted execs run as root with only SETUID, SETGID, KILL, CHOWN, and
DAC_OVERRIDE; privilege escalation is disabled and seccomp is RuntimeDefault.
Candidates receive none of those capabilities.

The explicit `-T anyeval_chart=false` template compatibility option selects the
provider's built-in Cilium chart for other clusters, with its CoreDNS dependency;
it is not the default AnyEval deployment path. Live gVisor boot logs, image digest,
node placement, and selecting policy must be checked by the deployment's provenance
hook; rendered YAML alone does not establish containment.

## Differences from upstream and validation

Upstream uses temperature 0.0 and describes results averaged over three runs. This
package uses one epoch and leaves generation settings to the caller. Prompts are
explicit translation instructions with the required target skeleton and fenced
answer contract; they are not byte-identical upstream generation templates.
Java cleaning retains upstream's truncation at a repeated `import java` after
character 100. COBOL cleaning retains duplicate WORKING-STORAGE removal and
section reordering after fence extraction. No additional section synthesis or
forced PROCEDURE rewrite is applied.

The independent 60/30-second compile/run limits differ from upstream's Java
30-second alarm around the combined operation and COBOL's 5-second command limits.
Fresh work directories, shell-free argv, bounded outputs/processes, UID isolation,
and sandbox resources also differ. Report prompting, generation settings, runtime
versions, hardware, and these limits with scores; numerical equivalence to an
upstream leaderboard run is not claimed.

Tests require Python dependencies in `[test]` and Helm 3 or 4 on PATH. They disable
network access and need no model, Docker daemon, or cluster. They check all records
against the supplied source, deterministic rebuilding, field-taint privacy,
comparison edge cases, fake-sandbox failures/cancellation/cleanup, authenticated
supervisor mechanics using authored fixtures, actual Helm rendering/strict lint,
and rejection of deliberately broken chart templates. Local supervisor fixtures
stub Linux credentials, prctl, memory/process limits, OOM preference, and UID sweeping; they are **not Linux containment
attestation**. Full JVM/GnuCOBOL execution and Linux isolation need the image.
Two opt-in Linux regressions are skipped unless running as root in a disposable
sandbox with an unused UID 65532 and `CJT_LINUX_CONTAINMENT=1`. They check actual
credentials/capabilities, protected supervisor memory/signals, detached descendant
cleanup, and independent cleanup after forcibly killing the supervisor.

The standalone `scripts/linux_regressions.py` runs the actual SETUP + RUNNER and
shared receipt verifier as root inside the reference image, with no Inspect
installation. It first checks real `javac`/`java` and `cobc`/COBOL startup under the
limits, then checks invalid UTF-8, detached children exhausting their fork budget,
aggregate memory allocation (three children allocating 600 MiB each), and
unbounded 1 MiB file writes until the disk watchdog kills the candidate. Each attack must produce an authenticated
INCORRECT outcome; success logs contain only stage, returncode, and boolean flags.
Regression failures additionally name the check (`step`, such as
`compiler_smoke:cobc`), exception class (`error`), and an allowlisted assertion
`label` when applicable. Exception text, candidate output, and keys are never
printed. The pre-setup UID check uses the cleanup sweep's live-process definition
(ignoring zombies) without killing processes. Both compiler smokes require a
`run` receipt; a successful compile-only receipt does not pass them.
When Docker is available, aggregate memory and disk exhaustion run in a fresh
`docker run --memory=2g --memory-swap=2g --pids-limit=128 --read-only
--volume /tmp --shm-size=16m`. The anonymous writable disk volume allows compiler
execution and is removed with the container. The memory case must sign
`memory_exceeded`; the disk case must sign `disk_exceeded=True` with a nonzero
returncode. The disk writer creates 64 MiB in its work directory and writes
without bound in a second `cjt-*` directory directly under `/tmp`, proving coverage
outside the work directory. Both directories use the independent cleanup path. Without
Docker, a real `prlimit` AS/DATA
budget of 512 MiB checks allocation failure and receipt survival; this fallback
does **not** attest cgroup OOM behavior. Docker availability with a broken daemon
is a failure, not a fallback. The checkout must be mounted at the same absolute
path on the Docker daemon host and in the script's container.

The operator-only Inspect task `scripts/k8s_regressions.py` uses the exact package
Kubernetes chart and values (gVisor, deny-all egress, read-only root, disk-backed
`/tmp` and Memory `/dev/shm`). It is not registered as a package task. With the operator's `KUBECONFIG`:

```bash
inspect eval scripts/k8s_regressions.py --model mockllm/model
```

It runs the real SETUP + RUNNER against invalid UTF-8, fork exhaustion, three
600 MiB allocating children, files until `disk_exceeded=True`, and a zero-exit parent leaving a
`setsid` child sleeping. CORRECT requires every signed receipt to match its
expected flags, independent cleanup to succeed, and a fresh sandbox exec to
confirm the pod remains usable after each case. Its JSON summary contains only
boolean flags, never candidate output, receipts, or keys. This production-runtime
check, including actual gVisor disk-watchdog containment, requires a live cluster;
local protocol tests do not attest it.

Operators can run the full Docker regression via Cloud Build (substitute the
reference image digest). The supplied build uses the Docker builder's client and
socket, a disposable 2 GiB/128 PID outer container, and a 2 GiB inner container
with a writable disk volume and the supervisor disk watchdog. The Docker client
is copied into `/workspace/.linux-regressions/docker` and passed with `--docker-cli`:

```bash
gcloud builds submit . --config scripts/cloudbuild-linux-regressions.yaml \
  --substitutions=_IMAGE=REGISTRY/IMAGE@sha256:DIGEST
# Without Docker, inside a disposable reference image with this checkout mounted:
python3 scripts/linux_regressions.py
```

These Linux/operator checks are separate from the default host unit suite and
must be run before treating the resource limits as reference-image validation.

```bash
python -m pytest -q
python -m pip wheel --no-deps --no-build-isolation . -w dist
python -m pip install --no-deps --target .build/wheel-env/site-packages dist/*.whl
python scripts/verify_wheel.py .build/wheel-env/site-packages
```

The wheel verifier changes to an empty directory, blocks sockets, excludes checkout
imports, and cold-discovers both tasks through the installed `inspect_ai` entry
point. The distribution is `eval-cobol-javatrans`, module `cobol_javatrans`, version
1.0.0, Python >=3.11. `[inspect]` pins Inspect 0.3.260; `[anyeval]` additionally pins
inspect-evals 0.19.0 and inspect-k8s-sandbox 0.13.0, matching the template. No runtime
code imports inspect-evals or wraps another benchmark.

`run.py --task <direction> --sample-id HumanEval/0 --model <provider/model>` runs one
literal sample and writes a test-free bundle. Actual serving receipts and live
sandbox provenance are left null for AnyEval to supply. Installing this package
alone does not register or deploy it in the AnyEval application: the application
still needs its pinned requirement, catalog entry, problem index, image digest,
and normal worker/app deployment.
