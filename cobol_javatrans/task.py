"""Bidirectional COBOL-JavaTrans tasks, one generation and one epoch (pass@1)."""
import os
from importlib.resources import files
from pathlib import Path
from inspect_ai import Task, task
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.solver import generate, system_message
from .dataset import load_records, manifest
from .prompts import SYSTEM_MESSAGE, user_prompt
from .scoring import translation_scorer


def record_to_sample(record: dict, direction: str) -> Sample:
    return Sample(id=record['task_id'], input=user_prompt(record, direction),
                  metadata={'task_id': record['task_id'], 'entry_point': record['entry_point']})


def load_dataset(direction: str) -> MemoryDataset:
    return MemoryDataset(name='COBOL-JavaTrans-' + direction,
                         samples=[record_to_sample(r, direction) for r in load_records()])


def _task(direction: str, sandbox_type: str, anyeval_chart: bool) -> Task:
    if sandbox_type not in {'k8s', 'docker'}:
        raise ValueError('sandbox_type must be k8s or docker')
    resources = files('cobol_javatrans')
    config = str(resources.joinpath('values.yaml' if sandbox_type == 'k8s' else 'compose.yaml'))
    if sandbox_type == 'k8s' and anyeval_chart:
        from k8s_sandbox import K8sSandboxEnvironmentConfig
        os.environ.setdefault('INSPECT_K8S_DEFAULT_NAMESPACE', 'anyeval-sandbox')
        config = K8sSandboxEnvironmentConfig(chart=str(resources.joinpath('chart')), values=Path(config))
    return Task(dataset=load_dataset(direction), solver=[system_message(SYSTEM_MESSAGE), generate()],
                scorer=translation_scorer(direction), sandbox=(sandbox_type, config), epochs=1, version='1.0.0',
                metadata={'metric': 'pass@1', 'dataset_provenance': {k: v for k, v in manifest().items() if k != 'task_ids'}})


@task
def cobol_to_java(sandbox_type: str = 'k8s', anyeval_chart: bool = True) -> Task:
    """Translate COBOL to Java; compile for 60s and execute Main for 30s."""
    return _task('cobol_to_java', sandbox_type, anyeval_chart)


@task
def java_to_cobol(sandbox_type: str = 'k8s', anyeval_chart: bool = True) -> Task:
    """Translate Java to COBOL; every upstream caller must pass."""
    return _task('java_to_cobol', sandbox_type, anyeval_chart)
