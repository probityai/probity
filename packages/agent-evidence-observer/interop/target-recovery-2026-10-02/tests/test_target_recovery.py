"""Real target lifecycle controls and reselected semantic packet refusals."""
from __future__ import annotations

import copy
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1]))
from target_common import CASES, load, sha, write
from target_reader import verify_saved
from target_common import withheld_sources


def reseal(root: Path) -> dict:
    manifest = load(root, 'artifact-manifest.json')
    for name in manifest:
        if (root / name).exists():
            manifest[name] = sha((root / name).read_bytes())
    (root / 'artifact-manifest.json').unlink()
    write(root / 'artifact-manifest.json', manifest)
    pins = load(root, 'consumer-pins.json')
    pins['planSha256'] = sha((root / 'plan-before-run.json').read_bytes())
    pins['artifactManifestSha256'] = sha((root / 'artifact-manifest.json').read_bytes())
    return pins


def replace_json(root: Path, name: str, mutation):
    value = load(root, name)
    mutation(value)
    (root / name).unlink()
    write(root / name, value)


def test_retained_target_process_population(retained):
    root, report = retained.root, retained.report
    assert report['targetProcesses'] == 14
    assert report['completedEffects'] == 3
    assert report['incompleteRefusals'] == 2
    assert report['startupRefusals'] == 2
    assert [row['id'] for row in report['records']] == list(CASES)
    assert verify_saved(root, load(root, 'consumer-pins.json'), retained.withheld) == report
    assert not list(root.rglob('*worker*.json'))


MUTATIONS = [
    ('restart-ready.json', lambda x: x['processes'][1].update(pid=x['processes'][0]['pid'])),
    ('restart-ready.json', lambda x: x['processes'][0].update(returncode=0)),
    ('restart-ready.json', lambda x: x['processes'][0].update(stderrHex='00')),
    ('crash-after-intent.json', lambda x: x['processes'][0].update(returncode=0)),
    ('crash-inside-effect.json', lambda x: x['processes'][0].update(fault='after-effect')),
    ('crash-after-effect.json', lambda x: x['processes'][0].update(returncode=75)),
    ('restart-ready.json', lambda x: x['processes'][0].update(ordinal=True)),
    ('restart-ready.json', lambda x: x['processes'][1]['result'].update(pid=False)),
    ('restart-ready.json', lambda x: x['http'].pop()),
    ('restart-ready.json', lambda x: x['http'][0].update(status=False)),
    ('restart-ready.json', lambda x: x['http'][1].update(url='http://127.0.0.1:1/dispatch')),
    ('restart-ready.json', lambda x: x['http'][1].update(requestHex='7b7d')),
    ('restart-ready.json', lambda x: x['http'][1].update(endedNs=x['http'][1]['startedNs'])),
    ('crash-after-effect.json', lambda x: x['http'][0].update(status=200)),
    ('crash-after-intent.json', lambda x: x['http'][2].update(status=200)),
    ('crash-inside-effect.json', lambda x: x.update(recovery=None)),
    ('crash-after-effect.json', lambda x: x['final'].update(revision=0)),
    ('restart-ready.json', lambda x: x['final'].update(contentHex='00')),
    ('restart-ready.json', lambda x: x['final'].update(effectId='0' * 64)),
    ('restart-ready.json', lambda x: x['final']['receipt']['payload'].update(witnessScope='HOST')),
    ('missing-store.json', lambda x: x['processes'][1].update(returncode=0)),
    ('changed-configuration.json', lambda x: x.update(final={})),
    ('restart-ready.json', lambda x: x.update(snapshot='crash-after-effect.sqlite')),
    ('concurrent-intent.json', lambda x: x['http'][1].update(startedNs=x['http'][-2]['endedNs'])),
    ('plan-before-run.json', lambda x: x['cases'].pop()),
    ('plan-before-run.json', lambda x: x.update(parallelDispatches=True)),
    ('plan-before-run.json', lambda x: x.update(witnessScope='HOST')),
    ('plan-before-run.json', lambda x: x['doesNotAssert'].pop()),
]


@pytest.mark.parametrize('name,mutation', MUTATIONS)
def test_reselected_semantic_mutation(retained, copied, name, mutation):
    root = copied
    replace_json(root, name, mutation)
    pins = reseal(root)
    with pytest.raises((ValueError, KeyError, TypeError)):
        verify_saved(root, pins, retained.withheld)


def test_rollback_signed_store_refused_by_retained_prefix(retained, copied):
    root = copied
    path = root / 'crash-after-effect.sqlite'
    database = sqlite3.connect(path)
    try:
        database.execute('DELETE FROM events WHERE sequence=3')
        database.commit()
    finally:
        database.close()
    with pytest.raises(ValueError):
        verify_saved(root, reseal(root), retained.withheld)


def test_wrong_external_pins_refused(retained):
    pins = copy.deepcopy(load(retained.root, 'consumer-pins.json'))
    pins['artifactManifestSha256'] = '0' * 64
    with pytest.raises(ValueError):
        verify_saved(retained.root, pins, retained.withheld)


def test_reader_requires_explicit_pins(retained):
    process = subprocess.run([sys.executable, str(Path(__file__).parents[1] / 'target_reader.py'), str(retained.root)], capture_output=True, timeout=10)
    assert process.returncode == 2
    assert b'--pins-file' in process.stderr


def test_cached_completion_cannot_be_relabelled_as_fresh_restart(retained, copied):
    from probity_observer.crypto import canonical
    root = copied
    def mutation(attempt):
        attempt['intermediate'] = copy.deepcopy(attempt['final'])
        attempt['processes'][1]['result']['initial'] = copy.deepcopy(attempt['final'])
        attempt['http'][0]['responseHex'] = canonical(attempt['final']).hex()
    replace_json(root, 'restart-ready.json', mutation)
    with pytest.raises(ValueError, match='fresh-ready-before-dispatch'):
        verify_saved(root, reseal(root), retained.withheld)


def test_unlisted_absence_and_mismatched_withheld_digest_refused(retained, copied):
    pins = load(copied, 'consumer-pins.json')
    (copied / 'sources/target_common.py').unlink()
    with pytest.raises(ValueError, match='artifact-digest|manifest'):
        verify_saved(copied, pins, retained.withheld)
    with pytest.raises(ValueError):
        verify_saved(retained.root, pins, {**retained.withheld, 'sources/target_run.py': '0' * 64})
