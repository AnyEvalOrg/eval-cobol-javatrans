"""Only kubelet-attributed resource failures may replace a missing receipt."""
import asyncio
import logging
import threading
from types import SimpleNamespace as NS

import pytest
from inspect_ai.scorer import INCORRECT
from inspect_ai.util._sandbox.events import SandboxEnvironmentProxy

from cobol_javatrans import sandbox_state as ss
from cobol_javatrans.publication import private_grading


def pod(*, phase='Running', reason=None, message=None, terminated=None, last=None, uid='sample-uid',
        exit_code=None, signal=None, last_exit_code=None, last_signal=None):
    def state(reason, code, sig):
        return NS(terminated=NS(reason=reason, exit_code=code, signal=sig, message=None)
                  if any(value is not None for value in (reason, code, sig)) else None)
    return NS(metadata=NS(uid=uid), status=NS(phase=phase, reason=reason, message=message,
        container_statuses=[NS(state=state(terminated, exit_code, signal),
                              last_state=state(last, last_exit_code, last_signal))]))


@pytest.mark.parametrize('kwargs,expected', [
    ({'phase': 'Failed', 'terminated': 'OOMKilled'}, ss.MEMORY_FAILURE),
    ({'last': 'OOMKilled'}, ss.MEMORY_FAILURE),
    ({'phase': 'Failed', 'terminated': 'Error', 'exit_code': 137}, ss.MEMORY_FAILURE),
    ({'terminated': 'Error', 'signal': 9, 'exit_code': 1}, ss.MEMORY_FAILURE),
    ({'last': 'Error', 'last_exit_code': 137}, ss.MEMORY_FAILURE),
    ({'last_signal': 9}, ss.MEMORY_FAILURE),
    ({'terminated': 'Error', 'exit_code': 1, 'signal': 15}, None),
    ({'phase': 'Failed', 'reason': 'Evicted', 'exit_code': 137}, None),
    ({'phase': 'Failed', 'reason': 'Evicted', 'last_signal': 9}, None),
    ({'phase': 'Failed', 'reason': 'Evicted', 'exit_code': 137,
      'message': 'ephemeral-storage'}, ss.STORAGE_FAILURE),
    ({'phase': 'Failed', 'reason': 'Evicted', 'message': 'Container exceeded ephemeral-storage limit. PRIVATE'}, ss.STORAGE_FAILURE),
    ({'phase': 'Failed', 'reason': 'Evicted', 'message': 'The node was low on resource: ephemeral-storage.'}, ss.STORAGE_FAILURE),
    ({}, None),  # lost exec / timeout -s KILL with an otherwise Running pod
    ({'phase': 'Unknown', 'reason': 'NodeNotReady'}, None),
    ({'phase': 'Failed', 'reason': 'Preempted', 'message': 'Spot preemption'}, None),
    ({'phase': 'Failed', 'reason': 'Evicted', 'message': 'Node memory pressure'}, None),
    ({'phase': 'Failed', 'reason': 'Evicted', 'message': 'Node PID pressure'}, None),
    ({'phase': 'Failed', 'reason': 'Evicted'}, None),
    ({'phase': 'Failed', 'reason': 'NodeShutdown', 'terminated': 'Error'}, None),
    ({'terminated': 'Error'}, None),  # Error without a kill is not attribution
    ({'phase': 'Pending', 'message': 'OOMKilled ephemeral-storage PRIVATE'}, None),
])
def test_classify_pod(kwargs, expected):
    score = ss.classify_pod(pod(**kwargs), NS(uid='sample-uid'))
    if expected is None:
        assert score is None
    else:
        assert score.value == INCORRECT and score.explanation == expected
        assert 'PRIVATE' not in score.model_dump_json()


@pytest.mark.parametrize('missing', [None, NS(status=None), NS(status=NS(container_statuses=[], phase='Running', reason=None, message=None))])
def test_no_status_is_no_evidence(missing):
    assert ss.classify_pod(missing) is None


def environment():
    provider = pytest.importorskip('k8s_sandbox')
    env = object.__new__(provider.K8sSandboxEnvironment)
    identity = NS(name='exact-pod', namespace='sample-namespace', context_name='sample-context', uid='sample-uid')
    env._pod = NS(info=identity)
    return SandboxEnvironmentProxy(env), identity


@pytest.mark.parametrize('termination', [dict(terminated='OOMKilled'),
    dict(terminated='Error', exit_code=137), dict(terminated='Error', signal=9)])
@pytest.mark.parametrize('outcome', ['oom', 'lookup_error', 'gone', 'replacement', 'not_ready_running', 'not_ready_unknown'])
def test_lookup_uses_provider_identity_context_and_bounded_client(monkeypatch, caplog, outcome, termination):
    from k8s_sandbox import _kubernetes_api as api
    env, identity = environment()
    calls = []

    def read(**kwargs):
        calls.append(kwargs)
        logging.getLogger('kubernetes.client.rest').warning('PRIVATE POD RESPONSE')
        if outcome == 'lookup_error':
            raise RuntimeError('PRIVATE LOOKUP ERROR')
        if outcome == 'gone':
            from kubernetes.client.exceptions import ApiException
            raise ApiException(status=404, reason='PRIVATE')
        if outcome.startswith('not_ready_'):
            return pod(phase='Running' if outcome.endswith('running') else 'Unknown', reason='NodeNotReady')
        return pod(**termination, uid='replacement' if outcome == 'replacement' else 'sample-uid')

    def client(context):
        assert context == 'sample-context'
        return NS(read_namespaced_pod_status=read)

    monkeypatch.setattr(api, 'k8s_client', client)
    assert ss.pod_identity(env) is identity
    with private_grading(env) as private:
        score = asyncio.run(ss.sandbox_failure(private, identity))
    assert calls == [dict(name='exact-pod', namespace='sample-namespace', _request_timeout=(1, 2))]
    assert 'PRIVATE' not in caplog.text
    if outcome == 'oom':
        assert score.value == INCORRECT and score.explanation == ss.MEMORY_FAILURE
    else:
        assert score is None


def test_lookup_bounds_even_a_stuck_config_helper(monkeypatch):
    env, identity = environment()
    release = threading.Event()
    done = threading.Event()

    def stuck(_):
        try:
            release.wait(5)
            return pod(terminated='OOMKilled')
        finally:
            done.set()

    monkeypatch.setattr(ss, '_read_pod', stuck)
    monkeypatch.setattr(ss, 'LOOKUP_SECONDS', 0.02)
    try:
        # asyncio.run must also return without waiting for its executor shutdown.
        assert asyncio.run(ss.sandbox_failure(env, identity)) is None
        assert not done.is_set()
    finally:
        release.set()
        assert done.wait(1)


def test_non_kubernetes_environment_does_not_query(monkeypatch):
    monkeypatch.setattr(ss, '_read_pod', lambda _: pytest.fail('unexpected lookup'))
    assert asyncio.run(ss.sandbox_failure(SandboxEnvironmentProxy(NS()))) is None


@pytest.mark.parametrize('identity', [None, NS(uid='different'), NS(uid=None), NS()])
@pytest.mark.parametrize('termination', [dict(exit_code=137), dict(signal=9), dict(last_exit_code=137)])
def test_sigkill_requires_captured_matching_uid(identity, termination):
    assert ss.classify_pod(pod(**termination), identity) is None


@pytest.mark.parametrize('outcome,exception_class,gone', [
    ('found', None, False), ('gone', 'ApiException', True),
    ('forbidden', 'ApiException', False), ('error', 'RuntimeError', False),
])
def test_lookup_diagnostics_only_retain_exception_class(monkeypatch, outcome, exception_class, gone):
    from kubernetes.client.exceptions import ApiException
    def read(identity):
        if outcome in ('gone', 'forbidden'):
            raise ApiException(status=404 if outcome == 'gone' else 403, reason='PRIVATE API BODY')
        if outcome == 'error':
            raise RuntimeError('PRIVATE EXCEPTION')
        return pod(exit_code=137)

    monkeypatch.setattr(ss, '_read_pod', read)
    evidence = {}
    result = asyncio.run(ss.read_sandbox_pod(None, NS(uid='sample-uid'), evidence=evidence))
    assert (result is not None) == (outcome == 'found')
    assert evidence == dict(lookup_failed=exception_class is not None,
                            exception_class=exception_class, pod_gone=gone)
    assert 'PRIVATE' not in str(evidence)


def test_lookup_timeout_diagnostics_do_not_change_after_worker_finishes(monkeypatch):
    release = threading.Event()
    done = threading.Event()
    def read(identity):
        try:
            release.wait(5)
            raise RuntimeError('PRIVATE')
        finally:
            done.set()

    monkeypatch.setattr(ss, '_read_pod', read)
    monkeypatch.setattr(ss, 'LOOKUP_SECONDS', 0.01)
    evidence = {}
    try:
        assert asyncio.run(ss.read_sandbox_pod(None, NS(uid='sample-uid'), evidence=evidence)) is None
        assert evidence == dict(lookup_failed=True, exception_class='TimeoutError', pod_gone=False)
    finally:
        release.set()
        assert done.wait(1)
    assert evidence['exception_class'] == 'TimeoutError'
