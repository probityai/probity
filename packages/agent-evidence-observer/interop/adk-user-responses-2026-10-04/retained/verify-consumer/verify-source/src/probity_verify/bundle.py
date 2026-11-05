"""Create and replay portable offline decision bundles.

A bundle carries the exact case, consumer policy, bound artifacts, and decision.
It is a replay format, not a signature or an assertion about who captured the
artifacts. A recipient must establish the policy and witness provenance.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from .cli import _invalid_constant, _load, _unique_object
from .common import MAX_ARTIFACT_BYTES, CaseError, _artifact
from .core import adjudicate, canonical_json, render_packet

_CONTROL_LIMIT = 1024 * 1024
_BUNDLE_LIMIT = 64 * 1024 * 1024
_MEMBER_LIMIT = 128
_CONTROLS = {"case.json", "policy.json", "decision.json"}


def _safe_member(name: str, label: str) -> str:
    path = PurePosixPath(name)
    if (not name or path.is_absolute() or name != str(path) or
            "\\" in name or "\x00" in name or
            any(part in {".", ".."} for part in name.split("/"))):
        raise CaseError(f"{label}.path: must be a normalized relative path")
    return f"artifacts/{name}"


def _artifact_member(artifact_id: Any, metadata: Any) -> str:
    if not isinstance(artifact_id, str) or not artifact_id:
        raise CaseError("artifact id: expected nonempty string")
    if not isinstance(metadata, dict) or not isinstance(metadata.get("path"), str):
        raise CaseError(f"artifacts.{artifact_id}.path: expected string")
    return _safe_member(metadata["path"], f"artifacts.{artifact_id}")


def _artifact_paths(case: Any) -> dict[str, dict]:
    """Map safe archive members to case artifact metadata.

    Parameters
    ----------
    case : Any
        Parsed case JSON.

    Returns
    -------
    dict[str, dict]
        Archive member names and their binding metadata.

    Raises
    ------
    CaseError
        If an artifact path is ambiguous or cannot be safely staged.
    """
    artifacts = case.get("artifacts") if isinstance(case, dict) else None
    if not isinstance(artifacts, dict) or not artifacts:
        raise CaseError("case.artifacts: expected nonempty object")
    paths: dict[str, dict] = {}
    for artifact_id, metadata in artifacts.items():
        member = _artifact_member(artifact_id, metadata)
        if member in paths:
            raise CaseError(f"duplicate artifact path: {metadata['path']}")
        paths[member] = metadata
    return paths


def _bound_files(case: dict, root: Path) -> dict[str, bytes]:
    """Read each case artifact only after its declared binding verifies."""
    by_path = _artifact_paths(case)
    by_id = {f"artifacts/{meta['path']}": artifact_id
             for artifact_id, meta in case["artifacts"].items()}
    files: dict[str, bytes] = {}
    for member, metadata in by_path.items():
        artifact_id = by_id[member]
        data, check = _artifact(root, metadata, f"artifacts.{artifact_id}")
        if data is None:
            raise CaseError(f"artifacts.{artifact_id}: cannot bundle {check['status']} artifact")
        files[member] = data
    return files


def _zip_entry(name: str, data: bytes) -> tuple[zipfile.ZipInfo, bytes]:
    """Set fixed metadata so identical inputs produce identical ZIP bytes."""
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    info.compress_type = zipfile.ZIP_STORED
    return info, data


def _write_bundle(path: Path, entries: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name in sorted(entries):
            info, data = _zip_entry(name, entries[name])
            archive.writestr(info, data)


def create_bundle(
    case_path: Path, policy_path: Path, output: Path, artifact_root: Path | None = None
) -> dict:
    """Write a deterministic bundle for a fully bound case.

    Parameters
    ----------
    case_path, policy_path : Path
        The case and separately held consumer policy.
    output : Path
        New ZIP path. Existing files are never replaced.
    artifact_root : Path | None
        Base directory for case artifact paths. Defaults to the case directory.

    Returns
    -------
    dict
        The decision recomputed from the bytes inside the bundle.

    Raises
    ------
    CaseError
        If a referenced artifact is missing, unbound, unsafe, or the replay
        differs from the decision made before packaging.
    """
    if output.exists() or output.is_symlink():
        raise CaseError(f"bundle already exists: {output}")
    case = _load(case_path)
    policy = _load(policy_path)
    files = _bound_files(case, artifact_root or case_path.parent)
    with tempfile.TemporaryDirectory() as directory:
        staged = Path(directory)
        for member, data in files.items():
            target = staged / member
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        result = adjudicate(case, policy, staged / "artifacts")
    entries = {
        "case.json": canonical_json(case),
        "policy.json": canonical_json(policy),
        "decision.json": canonical_json(result),
        **files,
    }
    with tempfile.NamedTemporaryFile(dir=output.parent, suffix=".zip", delete=False) as stream:
        temporary = Path(stream.name)
    try:
        _write_bundle(temporary, entries)
        if replay_bundle(temporary) != result:
            raise CaseError("bundled decision differs from replay")
        os.link(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
    return result


def _read_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int) -> bytes:
    if (info.is_dir() or info.compress_type != zipfile.ZIP_STORED or
            stat.S_IFMT(info.external_attr >> 16) not in {0, stat.S_IFREG} or
            info.file_size > limit):
        raise CaseError(f"unsafe or oversized bundle member: {info.filename}")
    with archive.open(info) as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise CaseError(f"oversized bundle member: {info.filename}")
    return data


def _read_bundle(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if len(names) > _MEMBER_LIMIT:
            raise CaseError("bundle has too many members")
        if len(names) != len(set(names)) or not _CONTROLS.issubset(names):
            raise CaseError("bundle has duplicate or missing control members")
        if sum(info.file_size for info in infos) > _BUNDLE_LIMIT:
            raise CaseError("bundle exceeds size limit")
        return {info.filename: _read_member(
            archive, info, _CONTROL_LIMIT if info.filename in _CONTROLS else MAX_ARTIFACT_BYTES
        ) for info in infos}


def _parse_json(data: bytes, label: str) -> Any:
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object,
                          parse_constant=_invalid_constant)
    except UnicodeDecodeError as exc:
        raise CaseError(f"{label}: expected UTF-8 JSON") from exc


def replay_bundle(path: Path) -> dict:
    """Recompute a bundled decision from only the carried policy and bytes.

    Parameters
    ----------
    path : Path
        Bundle created by :func:`create_bundle`.

    Returns
    -------
    dict
        Decision recomputed from the staged artifacts.

    Raises
    ------
    CaseError
        If bundle members are unsafe, incomplete, or disagree with the carried
        decision. Replay does not authenticate the policy or capture source.
    """
    entries = _read_bundle(path)
    case = _parse_json(entries["case.json"], "case.json")
    policy = _parse_json(entries["policy.json"], "policy.json")
    if (entries["case.json"] != canonical_json(case) or
            entries["policy.json"] != canonical_json(policy)):
        raise CaseError("case and policy must use canonical JSON")
    expected = _CONTROLS | set(_artifact_paths(case))
    if set(entries) != expected:
        raise CaseError("bundle members do not match case artifacts")
    with tempfile.TemporaryDirectory() as directory:
        staged = Path(directory)
        for member in sorted(expected - _CONTROLS):
            target = staged / member
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(entries[member])
        _bound_files(case, staged / "artifacts")
        result = adjudicate(case, policy, staged / "artifacts")
    if entries["decision.json"] != canonical_json(result):
        raise CaseError("bundled decision differs from replay")
    return result


def main(argv: list[str] | None = None) -> int:
    """Run the offline create or replay command."""
    parser = argparse.ArgumentParser(prog="probity-bundle")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("case", type=Path)
    create.add_argument("--policy", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--artifact-root", type=Path)
    replay = commands.add_parser("replay")
    replay.add_argument("bundle", type=Path)
    for command in (create, replay):
        command.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = (create_bundle(args.case, args.policy, args.output, args.artifact_root)
                  if args.command == "create" else replay_bundle(args.bundle))
    except (OSError, json.JSONDecodeError, zipfile.BadZipFile, CaseError) as exc:
        print(f"probity-bundle: {exc}", file=sys.stderr)
        return 2
    if args.json:
        sys.stdout.buffer.write(canonical_json(result))
    else:
        print(render_packet(result), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
