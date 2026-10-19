"""The box launcher pins one box, reverse-forwards the model tunnel and ships the job through box_run."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "basharena-box-run.sh"


def _dry(env: dict[str, str], *args: str) -> subprocess.CompletedProcess:
    base = {k: v for k, v in os.environ.items() if k not in {"BOX_RUN_HOSTS", "HPG_API_KEY"}}
    return subprocess.run([str(SCRIPT), *args], env=base | env | {"BASHARENA_DRY_RUN": "1"},
                          capture_output=True, text=True, cwd=SCRIPT.parent, check=False)


def test_the_dry_run_names_the_tunnel_and_the_box_run_job():
    done = _dry({"BOX_RUN_HOSTS": "root@10.0.0.9", "HPG_API_KEY": "k", "BOX_RUN_SH": "/x/box_run.sh"},
                "t1", "rows.jsonl", "openai-api/hpg/m", "/tmp/out", "8001", "--only", "5")
    assert done.returncode == 0, done.stderr
    tunnel, job = done.stdout.splitlines()
    assert "-R 127.0.0.1:18000:127.0.0.1:8001 root@10.0.0.9" in tunnel
    assert job.startswith("JOB HPG_BASE_URL=http://127.0.0.1:18000/v1 /x/box_run.sh t1 ")
    assert "--forward-env HPG_API_KEY" in job and "--fetch basharena-out/t1 /tmp/out" in job
    assert job.endswith("--only 5")


def test_more_than_one_box_is_refused():
    done = _dry({"BOX_RUN_HOSTS": "root@a,root@b", "HPG_API_KEY": "k"}, "t", "r", "m", "/o", "1")
    assert done.returncode == 64


def test_a_missing_model_key_is_refused():
    done = _dry({"BOX_RUN_HOSTS": "root@a"}, "t", "r", "m", "/o", "1")
    assert done.returncode != 0 and "HPG_API_KEY" in done.stderr
