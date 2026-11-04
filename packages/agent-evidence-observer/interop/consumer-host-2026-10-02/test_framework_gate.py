"""Publication-gate controls over installed commands and retained packets."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('installed_reader_fixtures',
    HERE.parent / 'framework-consumer-2026-10-02' / 'test_installed_readers.py')
assert spec is not None and spec.loader is not None
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


def policy_value(profile: str, pins: Path, listed: Path, change: str | None) -> dict:
    """Host policy for the original record, with one optional deliberate change."""
    value = {'schema': 'probity-framework-host-gate-v1', 'reader': profile,
             'profile': ('probity-langgraph-aae-ticket-v0' if profile == 'langgraph'
                         else 'probity-pydantic-ai-ticket-v0'),
             'plannedAttempts': 6 if profile == 'langgraph' else 5,
             'pinsSha256': hashlib.sha256(pins.read_bytes()).hexdigest(),
             'withheldSha256': hashlib.sha256(listed.read_bytes()).hexdigest()}
    value.update({'population': {'plannedAttempts': 100},
                  'profile': {'profile': 'other-native-profile'},
                  'withheld-digest': {'withheldSha256': '0' * 64}}.get(change, {}))
    if change == 'withheld-unpinned':
        del value['withheldSha256']
    return value


def invoke(tmp: Path, profile: str, change: str | None = None) -> subprocess.CompletedProcess[str]:
    """Invoke the public gate with the original native archive and external policy."""
    packet, pins = fixtures.selected_packet(profile, tmp / 'original')
    listed = fixtures.withheld_list(packet)
    policy = tmp / 'host-policy.json'
    value = policy_value(profile, pins, listed, change)
    policy.write_text(json.dumps(value))
    digest = hashlib.sha256(policy.read_bytes()).hexdigest()
    if change == 'policy-digest':
        digest = '0' * 64
    if change == 'pins-digest':
        pins.write_text('{}')
    if change == 'reader-refusal':
        (packet / 'artifact-manifest.json').write_text('{}')
    output = tmp / 'receipt'
    if change == 'stale-output':
        output.mkdir()
        (output / 'report.json').write_text('{"status":"verified"}')
    return subprocess.run([sys.executable, str(HERE / 'framework_gate.py'),
        '--packet', str(packet), '--pins', str(pins), '--policy', str(policy),
        '--policy-sha256', digest, '--withheld-sources', str(listed), '--reader-bin', str(Path(sys.executable).parent),
        '--output', str(output)], capture_output=True, text=True, timeout=60, check=False)


class TestFrameworkGate:
    class TestPassingCases:
        @pytest.mark.parametrize('profile', ['langgraph', 'pydantic'])
        def test_original_record_and_receipts(self, profile: str, tmp_path: Path) -> None:
            result = invoke(tmp_path, profile)
            assert result.returncode == 0, result.stdout + result.stderr
            receipt = tmp_path / 'receipt'
            assert json.loads((receipt / 'gate.json').read_bytes())['status'] == 'admitted'
            assert json.loads((receipt / 'child-status.json').read_bytes())['returncode'] == 0
            assert (receipt / 'report.json').read_bytes() == (receipt / 'reader.stdout').read_bytes()
            assert set(p.name for p in receipt.iterdir()) == {'host-policy.json', 'selected-pins.json',
                'launch.json', 'withheld-sources.json', 'child-status.json', 'reader.stdout', 'reader.stderr', 'report.json', 'gate.json'}
            report = json.loads((receipt / 'report.json').read_bytes())
            assert report['independentCustody'] == 'not-established'

    class TestFailingCases:
        @pytest.mark.parametrize('profile', ['langgraph', 'pydantic'])
        @pytest.mark.parametrize('change', ['population', 'profile', 'policy-digest',
            'pins-digest', 'withheld-digest', 'withheld-unpinned', 'reader-refusal', 'stale-output'])
        def test_refuses_without_publication(self, profile: str, change: str, tmp_path: Path) -> None:
            result = invoke(tmp_path, profile, change)
            assert result.returncode == 1
            if change == 'stale-output':
                assert 'output already exists' in result.stderr
            else:
                receipt = tmp_path / 'receipt'
                assert json.loads((receipt / 'gate.json').read_bytes())['status'] == 'refused'
                assert not (receipt / 'report.json').exists()
                if change == 'reader-refusal':
                    assert json.loads((receipt / 'child-status.json').read_bytes())['returncode'] == 1
                    assert json.loads((receipt / 'reader.stdout').read_bytes())['status'] == 'refused'


@pytest.mark.parametrize('mode', ['timeout', 'missing-report', 'duplicate-report', 'boolean-denominator'])
def test_broken_child_never_admits(mode: str, tmp_path: Path) -> None:
    """Installation/launch failures cannot borrow an old or contradictory report."""
    packet = tmp_path / 'packet'
    packet.mkdir()
    pins = tmp_path / 'pins.json'
    pins.write_text('{}')
    policy = tmp_path / 'policy.json'
    policy.write_text(json.dumps({'schema': 'probity-framework-host-gate-v1',
        'reader': 'langgraph', 'profile': 'selected', 'plannedAttempts': 1,
        'pinsSha256': hashlib.sha256(pins.read_bytes()).hexdigest()}))
    binary = tmp_path / 'probity-langgraph-read'
    bodies = {'timeout': 'import time; time.sleep(5)', 'missing-report': 'pass',
        'duplicate-report': 'print(\'{"status":"refused","status":"verified","profile":"selected","plannedAttempts":1,"records":[{}]}\')',
        'boolean-denominator': 'print(\'{"status":"verified","profile":"selected","plannedAttempts":true,"records":[{}]}\')'}
    binary.write_text('#!' + sys.executable + '\n' + bodies[mode] + '\n')
    binary.chmod(0o755)
    result = subprocess.run([sys.executable, str(HERE / 'framework_gate.py'),
        '--packet', str(packet), '--pins', str(pins), '--policy', str(policy),
        '--policy-sha256', hashlib.sha256(policy.read_bytes()).hexdigest(),
        '--reader-bin', str(tmp_path), '--output', str(tmp_path / 'receipt'), '--timeout', '1'],
        capture_output=True, text=True, timeout=10, check=False)
    assert result.returncode == 1
    receipt = tmp_path / 'receipt'
    assert json.loads((receipt / 'gate.json').read_bytes())['status'] == 'refused'
    assert not (receipt / 'report.json').exists()
    if mode == 'timeout':
        assert json.loads((receipt / 'child-status.json').read_bytes())['returncode'] == 124
