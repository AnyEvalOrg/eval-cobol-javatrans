"""Kernel-attributed backstop for missing receipts, never candidate diagnostics.

Provider identity/client APIs are pinned to inspect-k8s-sandbox 0.13.0. Watchdogs
keep ordinary failures alive long enough to sign; they cannot enumerate every
kind of retained kernel memory (SysV IPC, mappings, socket queues, pipes, etc.).
"""
from __future__ import annotations

import asyncio
from contextvars import copy_context
import threading

from inspect_ai.scorer import INCORRECT, Score
from inspect_ai.util._sandbox.events import SandboxEnvironmentProxy

MEMORY_FAILURE = "sandbox memory exhausted during candidate execution"
STORAGE_FAILURE = "sandbox storage exhausted during candidate execution"
LOOKUP_SECONDS = 4
# A stuck credential helper/DNS call must neither block scoring nor accumulate
# unbounded threads. Daemon workers also avoid asyncio.run's executor shutdown wait.
_LOOKUPS = threading.BoundedSemaphore(8)


def pod_identity(environment):
    """Snapshot the provider's immutable PodInfo AFTER setup, BEFORE runner exec."""
    try:
        from k8s_sandbox import K8sSandboxEnvironment

        if isinstance(environment, SandboxEnvironmentProxy):
            environment = environment._sandbox
        if isinstance(environment, K8sSandboxEnvironment):
            return environment._pod.info
    except Exception:
        pass
    return None


def classify_pod(pod, identity=None) -> Score | None:
    """Only kubelet resource evidence yields a verdict; never echo pod messages."""
    status = getattr(pod, "status", None)
    if status is None:
        return None
    same_uid = (identity is not None and getattr(identity, "uid", None) is not None
                and getattr(getattr(pod, "metadata", None), "uid", None) == identity.uid)
    for container in status.container_statuses or []:
        for state in (container.state, container.last_state):
            terminated = getattr(state, "terminated", None)
            if getattr(terminated, "reason", None) == "OOMKilled":
                return Score(value=INCORRECT, explanation=MEMORY_FAILURE)
            # Host-cgroup OOM can kill the runsc sandbox; containerd may report
            # Error/137 rather than OOMKilled. Require an actual container
            # termination on the captured pod, not the RUNNER exec's exit code.
            # Spot deletion (404) and NodeNotReady with Running/Unknown and no
            # terminated state provide no such evidence and remain harness errors.
            if (same_uid and status.reason != "Evicted" and terminated is not None
                    and (getattr(terminated, "exit_code", None) == 137
                         or getattr(terminated, "signal", None) == 9)):
                return Score(value=INCORRECT, explanation=MEMORY_FAILURE)
    if (status.phase == "Failed" and status.reason == "Evicted"
            and "ephemeral-storage" in (status.message or "").lower()):
        return Score(value=INCORRECT, explanation=STORAGE_FAILURE)
    return None


def _read_pod(identity):
    # Same config, in-cluster fallback, context and thread-local client factory
    # as the exec provider; never invoke kubectl or search other samples' pods.
    from k8s_sandbox._kubernetes_api import k8s_client

    pod = k8s_client(identity.context_name).read_namespaced_pod_status(
        name=identity.name, namespace=identity.namespace, _request_timeout=(1, 2))
    # A same-name replacement is infrastructure, not this candidate's failure.
    if pod.metadata.uid != identity.uid:
        return None
    return pod


async def read_sandbox_pod(environment, identity=None, *, evidence=None):
    """Bound the entire lookup, including config loading; failure returns no evidence."""
    # Operator regressions can retain lookup diagnostics without exposing API
    # bodies or exception text. Production scoring leaves this sink unset.
    if evidence is not None:
        evidence.update(lookup_failed=False, exception_class=None, pod_gone=False)
    identity = identity if identity is not None else pod_identity(environment)
    if identity is None or not _LOOKUPS.acquire(blocking=False):
        return None
    loop = asyncio.get_running_loop()
    future = loop.create_future()

    def deliver(result):
        if not future.done():
            future.set_result(result)

    def worker():
        pod = None
        exception_class = None
        pod_gone = False
        try:
            pod = _read_pod(identity)
        except Exception as exc:
            exception_class = type(exc).__name__
            from kubernetes.client.exceptions import ApiException
            pod_gone = isinstance(exc, ApiException) and exc.status == 404
        finally:
            _LOOKUPS.release()
        try:
            loop.call_soon_threadsafe(deliver, (pod, exception_class, pod_gone))
        except RuntimeError:
            pass  # The caller may already have closed its event loop.

    try:
        threading.Thread(target=copy_context().run, args=(worker,), daemon=True).start()
    except Exception as exc:
        _LOOKUPS.release()
        if evidence is not None:
            evidence.update(lookup_failed=True, exception_class=type(exc).__name__)
        return None
    try:
        async with asyncio.timeout(LOOKUP_SECONDS):
            pod, exception_class, pod_gone = await future
        if evidence is not None:
            evidence.update(lookup_failed=exception_class is not None,
                            exception_class=exception_class, pod_gone=pod_gone)
        return pod
    except Exception as exc:
        if evidence is not None:
            evidence.update(lookup_failed=True, exception_class=type(exc).__name__)
        return None


async def sandbox_failure(environment, identity=None) -> Score | None:
    try:
        identity = identity if identity is not None else pod_identity(environment)
        return classify_pod(await read_sandbox_pod(environment, identity), identity)
    except Exception:
        return None
