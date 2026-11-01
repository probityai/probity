"""The remote-host launcher pins one host, reverse-forwards the model tunnel and ships the job through its runner."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from probity_observer.done.basharena import run

SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "basharena-box-run.sh"


def _dry(env: dict[str, str], *args: str) -> subprocess.CompletedProcess:
    base = {k: v for k, v in os.environ.items() if k not in {"BOX_RUN_HOSTS", "BOX_RUN_SH", "REMOTE_API_KEY"}}
    return subprocess.run([str(SCRIPT), *args], env=base | env | {"BASHARENA_DRY_RUN": "1"},
                          capture_output=True, text=True, cwd=SCRIPT.parent, check=False)


def test_the_dry_run_names_the_tunnel_and_the_runner_job():
    done = _dry({"BOX_RUN_HOSTS": "root@10.0.0.9", "REMOTE_API_KEY": "k", "BOX_RUN_SH": "/x/runner.sh"},
                "t1", "rows.jsonl", "openai-api/remote/m", "/tmp/out", "8001", "--only", "5")
    assert done.returncode == 0, done.stderr
    tunnel, job = done.stdout.splitlines()
    assert "-R 127.0.0.1:18000:127.0.0.1:8001 root@10.0.0.9" in tunnel
    assert job.startswith("JOB REMOTE_BASE_URL=http://127.0.0.1:18000/v1 /x/runner.sh t1 ")
    assert "--forward-env REMOTE_API_KEY" in job and "--fetch basharena-out/t1 /tmp/out" in job
    assert job.endswith("--only 5")


def test_more_than_one_host_is_refused():
    done = _dry({"BOX_RUN_HOSTS": "root@a,root@b", "REMOTE_API_KEY": "k", "BOX_RUN_SH": "/x"},
                "t", "r", "openai-api/remote/m", "/o", "1")
    assert done.returncode == 64


def test_a_missing_runner_model_key_or_model_form_is_refused():
    full = {"BOX_RUN_HOSTS": "root@a", "REMOTE_API_KEY": "k", "BOX_RUN_SH": "/x"}
    for drop, word in (("BOX_RUN_SH", "BOX_RUN_SH"), ("REMOTE_API_KEY", "REMOTE_API_KEY")):
        done = _dry({k: v for k, v in full.items() if k != drop}, "t", "r", "openai-api/remote/m", "/o", "1")
        assert done.returncode != 0 and word in done.stderr
    done = _dry(full, "t", "r", "m", "/o", "1")
    assert done.returncode == 64 and "openai-api/<service>/<model>" in done.stderr


def test_the_episode_runner_forwards_only_the_models_own_variables():
    environ = {"MY_SERVER_BASE_URL": "u", "MY_SERVER_API_KEY": "k", "OTHER_API_KEY": "x"}
    assert run.model_env("openai-api/my-server/m", environ) == {"MY_SERVER_BASE_URL": "u", "MY_SERVER_API_KEY": "k"}
    assert run.model_env("model", environ) == {}
