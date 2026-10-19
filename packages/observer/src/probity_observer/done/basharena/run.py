"""The episode runner: drive one episode through every step of :mod:`.episode`, and many in a batch.

Usage (from the observer's environment)::

    python -m probity_observer.done.basharena.run --rows rows.jsonl --out <dir> --basharena <clone> \
        --observer-image <tag> --model openai-api/hpg/gpt-oss-120b --key <seed file> [--only <task id>...]

The model's endpoint and key come from the environment the Inspect provider reads (for
``openai-api/hpg/...``: ``HPG_BASE_URL`` and ``HPG_API_KEY``); they are passed to the driver and never
written to the episode directory.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from ..formats import load_signer, sha256
from . import contract, episode, observer, task, verdict
from .episode import Commands, Config, read_json, write_json


def _driver(config: Config, work: Path) -> subprocess.Popen:
    env = {k: v for k, v in os.environ.items() if not k.startswith("VIRTUAL_ENV")}
    env.update(config.model_env, BASH_ARENA_RUN_ID=work.name, INSPECT_LOG_LEVEL="warning")
    log = (work / "driver.log").open("wb")
    return subprocess.Popen(
        [str(config.basharena / ".venv" / "bin" / "python"), str(episode.resource("basharena_driver.txt")),
         "episode", "--row", str(work / "row.json"), "--model", config.model, "--episode-dir", str(work),
         "--max-steps", str(config.max_steps), "--time-limit", str(config.time_limit)],
        cwd=config.basharena, env=env, stdout=log, stderr=subprocess.STDOUT)


def _start_observer(cmd: Commands, config: Config, container: episode.Container, work: Path,
                    stem: str = "trace", reads: bool = False) -> str:
    program = work / f"{stem}.bt"
    program.write_text(observer.program(container.cgroup, reads=reads))
    log = work / f"{stem}.log"
    name = f"obs-{work.name}-{stem}-{int(time.time())}"
    env = [a for k, v in observer.ENV.items() for a in ("-e", f"{k}={v}")]
    cmd.run(["docker", "run", "-d", "--name", name, "--privileged", "--pid=host", *env, "-v",
             "/sys/kernel:/sys/kernel:ro", "-v", f"{work}:/out", config.observer_image, "bpftrace", "-o",
             f"/out/{stem}.log", f"/out/{stem}.bt"])
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        logs = cmd.run(["docker", "logs", name], check=False)
        text = (logs.stdout + logs.stderr).decode("utf-8", "replace")
        if "ERROR" in text or "error:" in text:
            raise RuntimeError(f"bpftrace failed: {text[-800:]}")
        if log.exists() and log.read_text(errors="replace").startswith("Attaching"):
            return name
        time.sleep(0.5)
    raise RuntimeError("bpftrace did not attach within 120 s")


def _stop_observer(cmd: Commands, name: str, work: Path) -> None:
    cmd.run(["docker", "stop", "-t", "30", name], check=False, timeout=120)
    logs = cmd.run(["docker", "logs", name], check=False)
    with (work / "observer.log").open("ab") as handle:
        handle.write(logs.stdout + logs.stderr)
    cmd.run(["docker", "rm", "-f", name], check=False)


def _start_guard(cmd: Commands, config: Config, container: episode.Container, image: str, runtime: bytes,
                 spec: task.Spec, work: Path) -> dict[str, Any]:
    runs = []
    for index in range(2):
        found = episode.cold_reading(cmd, container, image, f"{work.name}-guard{index}", work,
                                     lambda cid: episode.reading_sealed(cmd, cid, runtime, spec.tests))
        runs.append(found)
    write_json(work / "start-guard-readings.json", runs)
    if any(r["status"] != "ok" for r in runs):
        raise task.Refused(spec.task_id, "start_guard_unreadable", str([r["status"] for r in runs]))
    return {"runs": [{i: r["outcomes"].get(i, "error") for i in spec.test_ids} for r in runs]}


def _host_end(cmd: Commands, config: Config, container: episode.Container, work: Path) -> None:
    upper = episode.observe(cmd, config, container, "upper")
    write_json(work / "upper-end.json", upper)
    files = [p for p, e in upper["entries"].items() if e["type"] == "file"]
    lower = episode.observe(cmd, config, container, "lower", *files) if files else {}
    existing = [p for p in files if lower.get(p)]
    dpkg = episode.observe(cmd, config, container, "dpkg", *existing) if existing else {}
    write_json(work / "host-end.json", {
        "nat": episode.observe(cmd, config, container, "nat"),
        "preload": episode.observe(cmd, config, container, "preload"),
        "changed_image_binaries": episode.changed_image_binaries(upper, lower, dpkg)})


def _readings(cmd: Commands, config: Config, container: episode.Container, runtime: bytes, spec: task.Spec,
              work: Path) -> None:
    """The two live readings, with a second program recording every open for the grading window."""
    out = work / "readings"
    out.mkdir(exist_ok=True)
    grading = _start_observer(cmd, config, container, work, stem="trace-grading", reads=True)
    try:
        write_json(out / "L_s.json", episode.reading_sealed(cmd, container.id, runtime, spec.tests))
        write_json(out / "L_std.json", episode.reading_standard(cmd, container.id, spec.tests, work))
    finally:
        _stop_observer(cmd, grading, work)


def _cold_readings(cmd: Commands, container: episode.Container, final: str, runtime: bytes,
                   spec: task.Spec, work: Path) -> None:
    out = work / "readings"
    write_json(out / "C_s.json", episode.cold_reading(
        cmd, container, final, f"{work.name}-cs", work,
        lambda cid: episode.reading_sealed(cmd, cid, runtime, spec.tests)))
    write_json(out / "C_std.json", episode.cold_reading(
        cmd, container, final, f"{work.name}-cstd", work,
        lambda cid: episode.reading_standard(cmd, cid, spec.tests, work)))


def _teardown(cmd: Commands, container: episode.Container | None, images: list[str]) -> None:
    if container is not None:
        files = [a for f in container.compose_files.split(",") for a in ("-f", f)]
        cmd.run(["docker", "compose", "-p", container.project, *files, "down", "-v", "--remove-orphans"],
                check=False, timeout=600)
    for image in images:
        cmd.run(["docker", "image", "rm", "-f", image], check=False)


def run_episode(row: dict[str, Any], row_index: int, revision: str, config: Config, root: Path, key) -> dict:
    """Run one episode; return its verdict record. Raises :class:`task.Refused` for an unsealable task."""
    work = root / episode.episode_id(row)
    if (work / "verdict.json").exists():
        return read_json(work / "verdict.json")
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    write_json(work / "row.json", row)
    cmd = Commands(work / "commands.jsonl")
    spec = task.compile_spec(row, row_index, revision)
    driver = _driver(config, work)
    container, images, observer_name = None, [], None
    try:
        episode.wait_for(work / "ready.json", 3600, lambda: driver.poll() is None)
        container = episode.find_container(cmd, read_json(work / "ready.json")["hostname"])
        write_json(work / "container.json", container.__dict__)
        start = f"probity-start-{work.name}:latest"
        cmd.run(["docker", "commit", container.id, start], timeout=900)
        images.append(start)
        runtime = cmd.run(["docker", "run", "--rm", "-i", "--entrypoint", "sh", start, "-s"],
                          input=episode.resource("export_runtime.sh").read_bytes(), timeout=900).stdout
        guard = _start_guard(cmd, config, container, start, runtime, spec, work)
        images_ids = {"default": cmd.text(["docker", "image", "inspect", "-f", "{{.Id}}", start])}
        facts = contract.EnvironmentFacts(images=images_ids, runtime_sha256=sha256(runtime),
                                          base_environment_sha256=episode.base_environment_digest(config),
                                          start_guard=guard, in_process=False)
        sealed = contract.seal(spec, facts, work / "contract", key)
        observer_name = _start_observer(cmd, config, container, work)
        write_json(work / "upper-start.json", episode.observe(cmd, config, container, "upper"))
        write_json(work / "procs-start.json", episode.observe(cmd, config, container, "procs"))
        write_json(work / "go.json", {"monotonic_ns": time.monotonic_ns(), "wall": time.time()})
        driver.wait(timeout=config.time_limit + 1800)
        write_json(work / "run-end.json", {"monotonic_ns": time.monotonic_ns(), "driver_exit": driver.returncode})
        if not (work / "tools.json").exists():
            raise RuntimeError(f"driver exited {driver.returncode} without tools.json")
        write_json(work / "procs-end.json", episode.observe(cmd, config, container, "procs"))
        _host_end(cmd, config, container, work)
        final = f"probity-final-{work.name}:latest"
        cmd.run(["docker", "commit", container.id, final], timeout=900)
        images.append(final)
        _readings(cmd, config, container, runtime, spec, work)
        _stop_observer(cmd, observer_name, work)
        observer_name = None
        _cold_readings(cmd, container, final, runtime, spec, work)
        found = verdict.derive(episode.build_episode(work, spec, container))
        record = dict(found, contract_sha256=sealed.contract_sha256, episode=work.name,
                      task_id=spec.task_id, model=config.model)
        verdict.write(work, record, key)
        return record
    finally:
        if observer_name:
            _stop_observer(cmd, observer_name, work)
        if driver.poll() is None:
            driver.terminate()
        # BashArena's per-task images too: disk is the limit on this host, and a rerun rebuilds them.
        images += [f"bash-arena-default-{spec.task_id}:latest", f"bash-arena-database-server-{spec.task_id}:latest"]
        _teardown(cmd, container, images)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--basharena", required=True, type=Path)
    parser.add_argument("--observer-image", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--key", required=True, type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--max-steps", type=int, default=100)
    parser.add_argument("--only", nargs="*")
    args = parser.parse_args(argv)
    env = {k: os.environ[k] for k in os.environ if k.startswith("HPG_")}
    config = Config(args.basharena, args.observer_image, args.model, env, args.max_steps)
    key = load_signer(args.key)
    args.out.mkdir(parents=True, exist_ok=True)
    status = 0
    for line in args.rows.read_text().splitlines():
        item = json.loads(line)
        row, index = item["row"], item["index"]
        if args.only and str(row["task_id"]) not in args.only:
            continue
        try:
            record = run_episode(row, index, args.revision, config, args.out, key)
            print("VERDICT", row["task_id"], record["outcome"]["status"], record["integrity"]["status"],
                  [f["rule"] for f in record["integrity"]["findings"]], flush=True)
        except task.Refused as exc:
            write_json(args.out / f"refused-{row['task_id']}.json", {"reason": exc.reason, "detail": exc.detail})
            print("REFUSED", row["task_id"], exc.reason, flush=True)
        except Exception as exc:  # noqa: BLE001 - one episode's failure is recorded; the batch goes on
            write_json(args.out / f"failed-{row['task_id']}.json", {"error": repr(exc)[:4000]})
            print("FAILED", row["task_id"], repr(exc)[:300], flush=True)
            status = 1
    return status


if __name__ == "__main__":
    sys.exit(main())
