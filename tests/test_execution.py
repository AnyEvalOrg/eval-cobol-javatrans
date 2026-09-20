import pytest
from cobol_javatrans.execution import execution_request
from test_scoring import record


def test_java_exact_compile_and_assertion_main_protocol():
    r = record()
    request = execution_request('CANDIDATE', r, 'cobol_to_java')
    assert request['files'] == {'Solution.java': 'CANDIDATE', 'Main.java': 'import java.util.*;\nJAVA_PRIVATE_TESTS'}
    assert request['argv'] == ['javac', 'Solution.java', 'Main.java']
    assert request['run_argv'] == ['java', '-cp', '.', 'Main']
    assert request['timeout'] == 60 and request['run_timeout'] == 30


def test_cobol_exact_compile_and_filename_protocol():
    r = record()
    r['entry_point'] = 'has_close_elements'
    request = execution_request('CANDIDATE', r, 'java_to_cobol', r['tests'][0])
    assert request['argv'] == ['cobc', '-w', '-fformat=variable', '-x', 'call.cbl', 'solution.cbl']
    assert request['run_argv'] == ['./call']
    assert request['output_file'] == 'HAS-CLOSE-ELEMENTS.TXT'
    assert set(request['files']) == {'call.cbl', 'solution.cbl'}
    assert 'result' not in request


@pytest.mark.parametrize('name', ['../secret', 'bad/name', 'x;echo'])
def test_unsafe_entry_points_fail_closed(name):
    r = record()
    r['entry_point'] = name
    with pytest.raises(ValueError):
        execution_request('code', r, 'java_to_cobol', r['tests'][0])
