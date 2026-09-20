"""Offline, integrity-checked package data with original upstream ids."""
import gzip
import hashlib
import json
from importlib.resources import files


def manifest() -> dict:
    return json.loads(files('cobol_javatrans').joinpath('data/manifest.json').read_text(encoding='utf-8'))


def load_records() -> list[dict]:
    try:
        info = manifest()
        raw = files('cobol_javatrans').joinpath('data/problems.jsonl.gz').read_bytes()
        if hashlib.sha256(raw).hexdigest() != info['artifact_sha256']:
            raise ValueError('Checksum mismatch')
        records = [json.loads(line) for line in gzip.decompress(raw).splitlines()]
        ids = [r['task_id'] for r in records]
        if len(records) != 143 or len(set(ids)) != 143 or ids != info['task_ids']:
            raise ValueError('Invalid ids')
        return records
    except Exception:
        pass
    raise RuntimeError('Packaged dataset invalid; details withheld.') from None
