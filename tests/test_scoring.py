import asyncio
import json
from types import SimpleNamespace

import pytest
from inspect_ai.scorer import CORRECT, INCORRECT, Target
from inspect_ai.util import ExecResult, OutputLimitExceededError

import cobol_javatrans.scoring as scoring


class FakeSandbox:
    def __init__(self, results):
        self.results = iter(results)
        self.calls = []
        self.requests = []
        self.paths = []
        self.key = bytes(range(32))

    async def exec(self, cmd, input=None, **kwargs):
        self.calls.append((cmd, dict(kwargs, input=input)))
        if cmd[-1] == scoring.SETUP:
            self.requests.append(json.loads(input))
            self.paths.append(f"/tmp/cjt-fresh_{len(self.paths) + 1}")
            return result(json.dumps({"cwd": self.paths[-1], "key": self.key.hex()}))
        if cmd == scoring.CLEANUP_COMMAND:
            return result("", returncode=1)
        if cmd == scoring.QUIESCENCE_COMMAND:
            return result("", returncode=0)
        response = next(self.results)
        if isinstance(response, Exception):
            raise response
        if isinstance(response, str):
            # An untrusted response, e.g. forged provider completion status.
            return result(response)
        return result(signed_receipt(self.key, self.paths[-1], response.stdout,
                                     returncode=response.returncode))


def signed_receipt(key, cwd, output="2", **kwargs):
    import base64
    import hashlib
    import hmac
    body = json.dumps(dict(returncode=kwargs.get("returncode", 0),
                           timeout=kwargs.get("timeout", False),
                           overflow=kwargs.get("overflow", False), stage=kwargs.get("stage", "run"), cwd=cwd,
                           output=base64.b64encode(output.encode()).decode()))
    return json.dumps({"body": body, "tag": hmac.new(key, body.encode(), hashlib.sha256).hexdigest()})


def state(kind="java_to_cobol", completion=None, expected="2"):
    language = 'java' if kind == 'cobol_to_java' else 'cobol'
    if completion is None:
        completion = '```' + language + '\n       synthetic candidate\n```'
    return SimpleNamespace(sample_id="fixture", output=SimpleNamespace(completion=completion), metadata={})


def record(kind="java_to_cobol", expected="2", test_input="PRIVATE_CALLER"):
    return dict(task_id="fixture", entry_point="fixture", Java_tests="JAVA_PRIVATE_TESTS",
                COBOL_canonical_solution="SOURCE_COBOL", Java_canonical_solution="SOURCE_JAVA",
                COBOL_prompt="COBOL_SKELETON", Java_prompt="JAVA_SKELETON",
                tests=[dict(test=test_input, result=dict(value=expected, type_="Int")) for _ in range(2)])


@pytest.fixture(autouse=True)
def synthetic_records(monkeypatch):
    monkeypatch.setattr(scoring, "load_records", lambda: [record()])
    # No wall-clock waits in fake provider tests; Linux tests use real deadlines.
    sleep = asyncio.sleep
    async def no_sleep(delay):
        await sleep(0)
    monkeypatch.setattr(scoring.asyncio, "sleep", no_sleep)


def install_sandbox(monkeypatch, fake):
    from inspect_ai.util._sandbox.events import SandboxEnvironmentProxy
    monkeypatch.setattr(scoring, "sandbox", lambda: SandboxEnvironmentProxy(fake))


def result(stdout="2", returncode=0):
    return ExecResult(success=returncode == 0, returncode=returncode, stdout=stdout, stderr="")


WITHHELD = "Private sandbox operation failed; details withheld."


def assert_harness_failure(kind="java_to_cobol"):
    with pytest.raises(RuntimeError) as raised:
        asyncio.run(scoring.translation_scorer(kind)(state(kind), Target('')))
    assert str(raised.value) == WITHHELD
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert raised.value.__suppress_context__ is True
    return raised.value


@pytest.mark.parametrize("kind", ["cobol_to_java", "java_to_cobol"])
@pytest.mark.parametrize("outcome", ["correct", "runtime", "compile", "timeout", "overflow", "incomplete", "missing"])
def test_scorer_results_with_fake_sandbox(monkeypatch, kind, outcome):
    fields = dict(stage='compile' if outcome in {'compile', 'incomplete'} else 'run',
                  returncode=1 if outcome in {'runtime', 'compile'} else 0,
                  timeout=outcome == 'timeout', overflow=outcome == 'overflow')
    response = '' if outcome == 'missing' else signed_receipt(bytes(range(32)), '/tmp/cjt-fresh_1', **fields)
    responses = [response]
    if outcome == 'correct' and kind == 'java_to_cobol':
        responses.append(signed_receipt(bytes(range(32)), '/tmp/cjt-fresh_2'))
    fake = FakeSandbox(responses)
    install_sandbox(monkeypatch, fake)
    if outcome == 'missing':
        assert_harness_failure(kind)
    else:
        score = asyncio.run(scoring.translation_scorer(kind)(state(kind), Target('')))
        assert score.value == (CORRECT if outcome == 'correct' else INCORRECT)
        if outcome == 'incomplete':
            assert score.explanation == 'Test 1: run did not complete.'
    count = 2 if outcome == 'correct' and kind == 'java_to_cobol' else 1
    assert len(fake.calls) == count * 4
    assert len(set(fake.paths)) == count
    for setup, run, cleanup in zip(fake.calls[::4], fake.calls[1::4], fake.calls[2::4]):
        assert cleanup[0] == scoring.CLEANUP_COMMAND
        assert setup[0][:4] == ['timeout', '-s', 'KILL', '5s']
        assert run[0][:4] == ['timeout', '-s', 'KILL', '100s']
        assert run[1]['timeout'] == 100
        assert run[1]['timeout_retry'] is False
    for request in fake.requests:
        assert request['timeout'] == 60 and request['run_timeout'] == 30
        assert isinstance(request['argv'], list) and isinstance(request['run_argv'], list)
        assert 'bash' not in request['argv'] and 'sh' not in request['argv']


def test_every_cobol_test_must_pass(monkeypatch):
    fake = FakeSandbox([result(), result('9')])
    install_sandbox(monkeypatch, fake)
    score = asyncio.run(scoring.translation_scorer('java_to_cobol')(state(), Target('')))
    assert score.value == INCORRECT
    assert score.explanation == 'Test 2: wrong answer.'


def test_java_exit_zero_not_stdout_decides(monkeypatch):
    fake = FakeSandbox([result('arbitrary debug output')])
    install_sandbox(monkeypatch, fake)
    assert asyncio.run(scoring.translation_scorer('cobol_to_java')(state('cobol_to_java'), Target(''))).value == CORRECT


@pytest.mark.parametrize('language', ['java', 'cobol'])
@pytest.mark.parametrize('completion', ['no code', '```LANG\nunterminated', '```LANG\n \n```', '```LANG\na\n```\n```LANG\nb\n```'])
def test_missing_or_ambiguous_code_never_starts_sandbox(monkeypatch, language, completion):
    def forbidden():
        raise AssertionError('No sandbox should be requested')
    monkeypatch.setattr(scoring, 'sandbox', forbidden)
    direction = 'cobol_to_java' if language == 'java' else 'java_to_cobol'
    score = asyncio.run(scoring.translation_scorer(direction)(state(direction, completion.replace('LANG', language)), Target('')))
    assert score.value == INCORRECT


def test_expected_cobol_output_stays_on_host(monkeypatch):
    fake = FakeSandbox([TimeoutError()])
    install_sandbox(monkeypatch, fake)
    monkeypatch.setattr(scoring, 'load_records', lambda: [record(expected='"EXPECTED_SECRET"')])
    error = assert_harness_failure()
    assert 'EXPECTED_SECRET' not in json.dumps(fake.calls) + str(error)


def test_empty_test_suite_is_an_error(monkeypatch):
    empty = record()
    empty['tests'] = []
    monkeypatch.setattr(scoring, 'load_records', lambda: [empty])
    with pytest.raises(RuntimeError, match='details withheld'):
        asyncio.run(scoring.translation_scorer('java_to_cobol')(state(), Target('')))


def test_lost_supervisor_response_is_a_harness_error(monkeypatch):
    fake = FakeSandbox([ConnectionError("cluster unavailable")])
    install_sandbox(monkeypatch, fake)
    assert_harness_failure()
    assert fake.calls[-1][0] == scoring.QUIESCENCE_COMMAND


@pytest.mark.parametrize("kind", ["java_to_cobol", "cobol_to_java"])
def test_output_limit_is_a_harness_error(monkeypatch, kind):
    fake = FakeSandbox([OutputLimitExceededError("fixture limit", None)])
    install_sandbox(monkeypatch, fake)
    assert_harness_failure(kind)


@pytest.mark.parametrize("forgery", [
    "2<completed-sentinel-value-0>",
    signed_receipt(b"wrong key", "/tmp/cjt-fresh_1"),
    '{"returncode":0,"output":"2"}',
    signed_receipt(bytes(range(32)), "/tmp/cjt-fresh_1").replace('run', 'compile'),
])
def test_forged_completion_marker_or_receipt_is_a_harness_error(monkeypatch, forgery):
    fake = FakeSandbox([forgery])
    install_sandbox(monkeypatch, fake)
    assert_harness_failure()


def test_marker_inside_captured_candidate_output_cannot_hide_failure(monkeypatch):
    fake = FakeSandbox([result("2<completed-sentinel-value-0>", returncode=1)])
    install_sandbox(monkeypatch, fake)
    score = asyncio.run(scoring.translation_scorer("java_to_cobol")(state(), Target("")))
    assert score.value == INCORRECT
    assert "run error (exit 1)" in score.explanation


def test_provider_really_strips_the_forged_marker():
    execute = pytest.importorskip("k8s_sandbox._pod.execute")
    output, status = execute.ExecuteOperation._filter_sentinel_and_returncode(
        None, b"2<completed-sentinel-value-0>"
    )
    assert output == b"2" and status == 0


@pytest.mark.parametrize("field,value", [("timeout", True), ("overflow", True), ("returncode", 137)])
def test_authenticated_failure_channels(monkeypatch, field, value):
    fake = FakeSandbox([signed_receipt(bytes(range(32)), "/tmp/cjt-fresh_1", **{field: value})])
    install_sandbox(monkeypatch, fake)
    score = asyncio.run(scoring.translation_scorer("java_to_cobol")(state(), Target("")))
    assert score.value == INCORRECT


def test_setup_timeout_is_bounded_and_a_harness_error(monkeypatch):
    class HungSetup(FakeSandbox):
        async def exec(self, cmd, **kwargs):
            if cmd in (scoring.CLEANUP_COMMAND, scoring.QUIESCENCE_COMMAND):
                return await super().exec(cmd, **kwargs)
            assert cmd[:4] == ["timeout", "-s", "KILL", "5s"]
            assert kwargs["timeout"] == 5
            raise TimeoutError("private material")
    install_sandbox(monkeypatch, HungSetup([]))
    assert_harness_failure()


@pytest.mark.parametrize('response', [result(), result('3'), result(returncode=7), '',
                                      TimeoutError(), ConnectionError(),
                                      OutputLimitExceededError('synthetic', None)])
def test_uid_cleanup_is_a_separate_exec_on_every_run_outcome(monkeypatch, response):
    fake = FakeSandbox([response, response])
    install_sandbox(monkeypatch, fake)
    if isinstance(response, (str, Exception)):
        assert_harness_failure()
    else:
        asyncio.run(scoring.translation_scorer("java_to_cobol")(state(), Target('')))
    runs = [i for i, (cmd, _) in enumerate(fake.calls) if scoring.RUNNER in cmd]
    assert runs
    for index in runs:
        cmd, kwargs = fake.calls[index + 1]
        assert cmd == scoring.CLEANUP_COMMAND
        assert cmd[-4:] == ['/usr/bin/pkill', '-KILL', '-u', '65532']
        assert kwargs['input'] is None and kwargs['cwd'] == '/'
        assert kwargs['timeout'] == 5 and kwargs['timeout_retry'] is False


def test_missing_receipt_waits_through_host_deadline_before_uid_sweep(monkeypatch):
    events = []

    async def wait(delay):
        assert 104 <= delay <= 105  # compile + run + supervisor overhead + host grace
        events.append('deadline')

    class MissingSupervisor(FakeSandbox):
        async def exec(self, cmd, **kwargs):
            if cmd == scoring.CLEANUP_COMMAND:
                assert events == ['deadline']
                events.append('sweep')
            return await super().exec(cmd, **kwargs)

    monkeypatch.setattr(scoring.asyncio, 'sleep', wait)
    fake = MissingSupervisor([''])
    install_sandbox(monkeypatch, fake)
    assert_harness_failure()
    assert events == ['deadline', 'sweep']


@pytest.mark.parametrize('failure', [TimeoutError(), ConnectionError(), result('', returncode=2)])
def test_cleanup_failure_aborts_before_next_test(monkeypatch, failure):
    class FailedCleanup(FakeSandbox):
        async def exec(self, cmd, **kwargs):
            if cmd == scoring.CLEANUP_COMMAND:
                self.calls.append((cmd, kwargs))
                if isinstance(failure, Exception):
                    raise failure
                return failure
            return await super().exec(cmd, **kwargs)

    fake = FailedCleanup([result()])
    install_sandbox(monkeypatch, fake)
    with pytest.raises(RuntimeError, match='details withheld'):
        asyncio.run(scoring.translation_scorer("java_to_cobol")(state(), Target('')))
    assert len(fake.paths) == 1
    assert fake.calls[-1][0] == scoring.CLEANUP_COMMAND


def test_scorer_cancellation_still_awaits_independent_uid_sweep(monkeypatch):
    class CancelledRun(FakeSandbox):
        async def exec(self, cmd, **kwargs):
            if scoring.RUNNER in cmd:
                raise asyncio.CancelledError()
            return await super().exec(cmd, **kwargs)

    fake = CancelledRun([])
    install_sandbox(monkeypatch, fake)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(scoring.translation_scorer("java_to_cobol")(state(), Target('')))
    assert fake.calls[-1][0] == scoring.QUIESCENCE_COMMAND


@pytest.mark.parametrize('failure', [TimeoutError(), ConnectionError(),
                                   OutputLimitExceededError('private material', None)])
def test_setup_failure_also_issues_uid_cleanup(monkeypatch, failure):
    class FailedSetup(FakeSandbox):
        async def exec(self, cmd, **kwargs):
            if scoring.SETUP in cmd:
                raise failure
            return await super().exec(cmd, **kwargs)

    fake = FailedSetup([])
    install_sandbox(monkeypatch, fake)
    assert_harness_failure()
    assert fake.calls[-1][0] == scoring.QUIESCENCE_COMMAND


def test_cleanup_requires_quiescence_before_reusing_sandbox(monkeypatch):
    class StillRunning(FakeSandbox):
        async def exec(self, cmd, **kwargs):
            if cmd == scoring.QUIESCENCE_COMMAND:
                self.calls.append((cmd, kwargs))
                return result('', returncode=2)
            return await super().exec(cmd, **kwargs)
    fake = StillRunning([result()])
    install_sandbox(monkeypatch, fake)
    with pytest.raises(RuntimeError, match='details withheld'):
        asyncio.run(scoring.translation_scorer('java_to_cobol')(state(), Target('')))
    assert len(fake.paths) == 1
    assert fake.calls[-1][0] == scoring.QUIESCENCE_COMMAND


def test_receipt_for_another_directory_is_a_harness_error(monkeypatch):
    fake = FakeSandbox([signed_receipt(bytes(range(32)), '/tmp/cjt-other')])
    install_sandbox(monkeypatch, fake)
    assert_harness_failure()


@pytest.mark.parametrize('stage', ['setup', 'runner'])
def test_exec_that_never_returns_is_a_harness_error_and_still_cleans_up(monkeypatch, stage):
    timeout = asyncio.timeout
    deadlines = []

    def short_timeout(delay):
        deadlines.append(delay)
        return timeout(0.01)

    class HungExec(FakeSandbox):
        async def exec(self, cmd, **kwargs):
            if (scoring.SETUP if stage == 'setup' else scoring.RUNNER) in cmd:
                await asyncio.Event().wait()
            return await super().exec(cmd, **kwargs)

    fake = HungExec([])
    install_sandbox(monkeypatch, fake)
    monkeypatch.setattr(scoring.asyncio, 'timeout', short_timeout)
    assert_harness_failure()
    assert deadlines == ([10, 10, 10] if stage == 'setup' else [10, 105, 10, 10])
    assert [cmd for cmd, _ in fake.calls[-2:]] == [scoring.CLEANUP_COMMAND, scoring.QUIESCENCE_COMMAND]


@pytest.mark.parametrize('response', [
    '',
    '{"returncode":0,"output":"2"}',
    signed_receipt(b'wrong key', '/tmp/cjt-fresh_1'),
    signed_receipt(bytes(range(32)), '/tmp/cjt-fresh_1').replace('run', 'compile'),
    signed_receipt(bytes(range(32)), '/tmp/cjt-other'),
    TimeoutError('PRIVATE_EXCEPTION'),
    OutputLimitExceededError('PRIVATE_STDOUT', 'PRIVATE_STDERR'),
    ConnectionError('PRIVATE_STDIN PRIVATE_CODE'),
], ids=['missing', 'unsigned', 'bad-signature', 'tampered', 'wrong-cwd',
        'exec-timeout', 'output-limit', 'lost-response'])
def test_receipt_rejection_is_an_inspect_sample_error_without_a_score(monkeypatch, tmp_path, response):
    from inspect_ai import Task, eval
    from inspect_ai.dataset import Sample
    from inspect_ai.model import ModelOutput
    from inspect_ai.solver import solver
    from inspect_ai._util import appdirs

    # Keep Inspect's trace files and caches inside the test's writable directory.
    monkeypatch.setattr(appdirs, 'user_data_path', lambda package: tmp_path / 'data' / package)
    monkeypatch.setattr(appdirs, 'user_cache_path', lambda package: tmp_path / 'cache' / package)

    @solver
    def candidate():
        async def solve(task_state, generate):
            task_state.output = ModelOutput.from_content('mockllm/model', state().output.completion)
            return task_state
        return solve

    fake = FakeSandbox([response])
    install_sandbox(monkeypatch, fake)
    task = Task(dataset=[Sample(id='fixture', input='Translate the fixture.')],
                solver=candidate(), scorer=scoring.translation_scorer('java_to_cobol'))
    log, = eval(task, model='mockllm/model', log_dir=str(tmp_path), display='none',
                fail_on_error=False)
    sample, = log.samples
    assert sample.error is not None
    assert sample.error.message == repr(RuntimeError(WITHHELD))
    assert not sample.scores
    assert not any(event.event == 'score' for event in sample.events)
    assert 'PRIVATE_' not in sample.error.model_dump_json()
    assert fake.calls[-1][0] == scoring.QUIESCENCE_COMMAND
