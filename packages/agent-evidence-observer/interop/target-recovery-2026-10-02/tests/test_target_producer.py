"""Producer-side lifecycle controls for the live target process runner."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1]))
from target_common import load
import target_run


@pytest.fixture(scope='session')
def fresh(tmp_path_factory):
    root = tmp_path_factory.mktemp('native') / 'packet'
    report = target_run.run(root, '0' * 40)
    return root, report


def test_real_target_process_population(fresh):
    assert fresh[1]['targetProcesses'] == 14


def test_startup_timeout_reaps_owned_process(monkeypatch, tmp_path):
    _, store = target_run.selected(tmp_path, tmp_path, 'timeout-run', 'restart-ready')
    actual = target_run.subprocess.Popen
    children = []
    def sleeping(command, **kwargs):
        process = actual([sys.executable, '-c', 'import time; time.sleep(30)'], **kwargs)
        children.append(process)
        return process
    monkeypatch.setattr(target_run.subprocess, 'Popen', sleeping)
    with pytest.raises(ValueError, match='target-startup-timeout'):
        target_run.start(tmp_path, store, store.readback()['receipt'], 1, timeout=0.05)
    assert children[0].poll() == -15
    receipt = load(tmp_path, 'cleanup-1.json')
    assert receipt['pid'] == children[0].pid
    assert receipt['reason'] == 'abnormal-execution-cleanup'


def test_http_exception_reaps_started_target(monkeypatch, tmp_path):
    private = tmp_path / 'host'
    private.mkdir()
    case, store = target_run.selected(tmp_path, private, 'failure-run', 'crash-after-intent')
    def failed_exchange(*args, **kwargs):
        raise RuntimeError('forced-http-failure')
    monkeypatch.setattr(target_run, 'exchange', failed_exchange)
    with pytest.raises(RuntimeError, match='forced-http-failure'):
        target_run.execute(tmp_path, private, case, store)
    receipt = load(private, 'cleanup-1.json')
    assert receipt['returncode'] == -15
    assert target_run.ACTIVE == []
