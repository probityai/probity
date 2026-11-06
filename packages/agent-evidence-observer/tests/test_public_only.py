"""The public package imports, verifies and re-reads every retained record with the producer refused.

Each check runs in a fresh ``python -I`` child whose import finder refuses every module that
scripts/release-freeze.toml keeps out of a release, so a public module, the command-line
verifier or a retained-record driver that still reaches that code fails here.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
import tomllib
from pathlib import Path

import probity_observer
import pytest
from fixture_records import RECORDS, manifest, materialize, pinned_keys

PACKAGE = Path(__file__).resolve().parents[1]
FREEZE = PACKAGE.parents[1] / "scripts" / "release-freeze.toml"
SOURCE = Path(probity_observer.__file__).resolve().parents[1]


def refused_modules() -> list[str]:
    """Read the module names the release freeze refuses for this distribution."""
    entries = tomllib.loads(FREEZE.read_text(encoding="utf-8"))["distribution"]["agent-evidence-observer"]["refuse"]
    names = [entry.removesuffix(".py").removesuffix("/").replace("/", ".") for entry in entries
             if entry.startswith("probity_observer/") and (entry.endswith(".py") or entry.endswith("/"))]
    assert names, "the release freeze names no probity_observer module"
    return sorted(names)


BOOT = textwrap.dedent(
    """
    import importlib.abc, json, runpy, sys
    source, refused, mode, target, *argv = sys.argv[1:]
    refused = json.loads(refused)
    sys.path.insert(0, source)

    class Refuse(importlib.abc.MetaPathFinder):
        def find_spec(self, name, path=None, target=None):
            if any(name == item or name.startswith(item + ".") for item in refused):
                raise ImportError(f"FROZEN module imported: {name}")
            return None

    sys.meta_path.insert(0, Refuse())
    sys.argv = [target, *argv]
    if mode == "module":
        runpy.run_module(target, run_name="__main__", alter_sys=True)
    elif mode == "path":
        sys.path.insert(0, str(__import__("pathlib").Path(target).parent))
        runpy.run_path(target, run_name="__main__")
    else:
        exec(compile(target, "<check>", "exec"), {"__name__": "__main__", "argv": argv, "refused": refused})
    """
)

IMPORT_ALL = textwrap.dedent(
    """
    import importlib, pathlib, probity_observer
    root = pathlib.Path(probity_observer.__file__).parent
    imported, skipped = [], []
    for path in sorted(root.rglob("*.py")):
        parts = ("probity_observer", *path.relative_to(root).with_suffix("").parts)
        name = ".".join(parts[:-1] if parts[-1] == "__init__" else parts)
        if parts[-1] == "__main__" or any(name == item or name.startswith(item + ".") for item in refused):
            continue
        try:
            importlib.import_module(name)
        except ModuleNotFoundError as exc:
            if exc.name is None or exc.name.split(".")[0] == "probity_observer":
                raise
            skipped.append(f"{name}: {exc.name}")
            continue
        imported.append(name)
    for line in skipped:
        print("skipped optional extra", line)
    print("imported", len(imported))
    """
)

RECORD_CHECKS = textwrap.dedent(
    """
    import json, pathlib
    from probity_observer.crypto import strict_loads
    from probity_observer.ledger import verify_ledger_head, verify_ledger_receipts
    from probity_observer.verify import verify_incomplete
    checked = 0
    for name in argv:
        record = pathlib.Path(name)
        keys = strict_loads((record / "trusted-keys.json").read_bytes())
        if (record / "incomplete.json").is_file():
            incomplete = strict_loads((record / "incomplete.json").read_bytes())
            try:
                event = verify_incomplete(record / "history.jsonl", incomplete["startCheckpoint"], incomplete["checkpoint"],
                                          keys["observer"], keys["witness"])
            except ValueError as exc:
                assert record.name == "abort-unknown-event" and "unknown event kind" in str(exc), (record, exc)
            else:
                assert event == incomplete["event"], record
            checked += 1
        head = record / ("fork-head.json" if (record / "fork-head.json").is_file() else "retained-head.json")
        if head.is_file():
            verify_ledger_head(record / "ledger.jsonl", strict_loads(head.read_bytes()), keys["witness"])
            checked += 1
        if (record / "start-checkpoint.json").is_file() and (record / "packet.json").is_file():
            packet = strict_loads((record / "packet.json").read_bytes())
            verify_ledger_receipts(record / "ledger.jsonl", packet["startCheckpoint"], packet["checkpoint"], keys["witness"])
            checked += 1
    print("checked", checked)
    """
)


def child(mode: str, target: str, *argv: str) -> subprocess.CompletedProcess[str]:
    """Run one check in an isolated interpreter that refuses the frozen modules."""
    command = [sys.executable, "-I", "-c", BOOT, str(SOURCE), json.dumps(refused_modules()), mode, target, *argv]
    return subprocess.run(command, capture_output=True, text=True, check=False, timeout=300)


def records(*layouts: str) -> list[str]:
    return sorted(name for name, entry in manifest()["records"].items() if entry["layout"] in layouts)


def test_refused_list_tracks_the_release_freeze() -> None:
    refused = refused_modules()
    assert {"probity_observer.broker", "probity_observer.producer_cli", "probity_observer.workload_runner"} <= set(refused)


def test_every_public_module_imports_without_the_frozen_modules() -> None:
    result = child("exec", IMPORT_ALL)
    assert result.returncode == 0, result.stderr
    print(result.stdout)
    assert int(result.stdout.split()[-1]) >= 40, result.stdout


@pytest.mark.parametrize("name", records("packet"))
def test_command_line_verifies_each_retained_packet(tmp_path: Path, name: str) -> None:
    record = materialize(name, tmp_path)
    result = child("module", "probity_observer.cli", "verify", str(record))
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["status"] == "verified"


@pytest.mark.parametrize("name", records("boundary", "workload"))
def test_command_line_verifies_each_retained_run(tmp_path: Path, name: str) -> None:
    record = materialize(name, tmp_path)
    layout = manifest()["records"][name]
    observer, witness = pinned_keys(record)
    result = child("module", "probity_observer.cli", f"verify-{layout['layout']}", str(record),
                   "--observer-key", observer, "--witness-key", witness)
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output["status"] == "verified"
    assert output[f"{layout['layout']}Status"] == layout["status"]


def test_retained_incomplete_and_ledger_records_verify(tmp_path: Path) -> None:
    names = [str(materialize(name, tmp_path)) for name in sorted(manifest()["records"])
             if (RECORDS / name / "trusted-keys.json").is_file()]
    result = child("exec", RECORD_CHECKS, *names)
    assert result.returncode == 0, result.stderr
    assert int(result.stdout.split()[-1]) >= 12, result.stdout


# A driver that needs a runtime outside the core package (a Node verifier and the
# profile's own reader package) runs in its profile workflow instead of here.
PROFILE_RUNTIME_DRIVERS = {
    "aps-durable-refund-2026-10-05": "package-observer-aps-durable-refund.yml",
    "authority-unreachable-2026-10-03": "package-observer-authority-unreachable.yml",
}


def test_each_interop_retained_driver_passes() -> None:
    drivers = sorted(path for path in PACKAGE.glob("interop/*/verify_retained.py")
                     if path.parent.name not in PROFILE_RUNTIME_DRIVERS)
    for driver in drivers:
        result = child("path", str(driver))
        assert result.returncode == 0, f"{driver}: {result.stdout}{result.stderr}"
    print("interop retained drivers checked:", len(drivers))


@pytest.mark.parametrize("profile", sorted(PROFILE_RUNTIME_DRIVERS))
def test_each_profile_runtime_driver_runs_in_its_workflow(profile: str) -> None:
    assert (PACKAGE / "interop" / profile / "verify_retained.py").is_file()
    workflow = (PACKAGE.parents[1] / ".github/workflows" / PROFILE_RUNTIME_DRIVERS[profile]).read_text()
    step = workflow.split(f"working-directory: packages/agent-evidence-observer/interop/{profile}\n")
    assert any("verify_retained.py" in part.split("- name:")[0] for part in step[1:]), profile
