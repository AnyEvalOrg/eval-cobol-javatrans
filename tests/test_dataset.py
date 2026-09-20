import ast
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import pytest
from cobol_javatrans.dataset import load_records, manifest
from cobol_javatrans.task import load_dataset, record_to_sample


def test_all_records_and_ids_exactly_match_upstream():
    original = [json.loads(line) for line in Path('COBOL-JavaTrans.jsonl').read_text().splitlines()]
    packaged = load_records()
    assert len(packaged) == 143
    if packaged != original:
        pytest.fail('Packaged records differ from upstream')
    info = manifest()
    assert info['task_ids'] == [r['task_id'] for r in original]
    assert len(set(info['task_ids'])) == 143
    assert hashlib.sha256(Path('COBOL-JavaTrans.jsonl').read_bytes()).hexdigest() == info['source_sha256']
    assert hashlib.sha256(('\n'.join(info['task_ids'])+'\n').encode()).hexdigest() == info['ids_sha256']
    for direction in ('cobol_to_java', 'java_to_cobol'):
        assert [s.id for s in load_dataset(direction)] == info['task_ids']


@pytest.mark.parametrize('direction,allowed', [
    ('cobol_to_java', {'COBOL_canonical_solution', 'Java_prompt'}),
    ('java_to_cobol', {'Java_canonical_solution', 'COBOL_prompt'}),
])
def test_prompt_uses_only_source_program_and_target_skeleton(direction, allowed):
    for r in load_records():
        sample = record_to_sample(r, direction)
        tainted = {k: v if k in allowed | {'task_id', 'entry_point'} else 'PRIVATE_SENTINEL' for k, v in r.items()}
        if record_to_sample(tainted, direction).input != sample.input:
            pytest.fail('Private target/test data changed prompt')
        assert 'PRIVATE_SENTINEL' not in record_to_sample(tainted, direction).input
        assert set(sample.metadata) == {'task_id', 'entry_point'}
        assert not sample.target
        for field in allowed:
            if r[field] not in sample.input:
                pytest.fail('Missing required source or target skeleton')


def test_all_expected_values_are_safe_literals_and_all_callers_retained():
    tests = [t for r in load_records() for t in r['tests']]
    assert len(tests) == manifest()['cobol_test_count'] == 807
    for t in tests:
        ast.literal_eval(t['result']['value'])
        assert t['test']


def test_rebuild_is_deterministic():
    paths = [Path('cobol_javatrans/data') / name for name in ('problems.jsonl.gz', 'manifest.json')]
    before = [p.read_bytes() for p in paths]
    subprocess.run([sys.executable, 'scripts/build_dataset.py'], check=True, capture_output=True, timeout=10)
    assert before == [p.read_bytes() for p in paths]
