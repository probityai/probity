"""Real descriptor and filesystem controls for the shared artifact boundary."""

import hashlib
import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from probity_verify.common import CaseError, MAX_ARTIFACT_BYTES, _artifact


def metadata(data=b"retained evidence", path="evidence.bin"):
    return {"path": path, "sha256": hashlib.sha256(data).hexdigest(), "length": len(data)}


def read(root, data=b"retained evidence", path="evidence.bin"):
    return _artifact(root, metadata(data, path), "artifacts.evidence")


def intercept_open(monkeypatch, callback):
    original = os.open
    def intercepted(name, flags, mode=0o777, *, dir_fd=None):
        return callback(original, name, flags, mode, dir_fd)
    monkeypatch.setattr(os, "open", intercepted)
    monkeypatch.setattr(os, "supports_dir_fd", os.supports_dir_fd | {intercepted})


@pytest.mark.parametrize("data", [b"", b"retained evidence", b"a" * (128 * 1024)])
def test_regular_files_bind_exact_bytes(tmp_path, data):
    (tmp_path / "evidence.bin").write_bytes(data)
    actual, binding = read(tmp_path, data)
    assert actual == data
    assert binding == {"status": "bound", **metadata(data)}


def test_missing_leaf_and_parent_are_unavailable(tmp_path):
    for path in ("evidence.bin", "absent/evidence.bin"):
        assert read(tmp_path, path=path) == (None, {"status": "unavailable", "path": path})


@pytest.mark.parametrize("path", ["../outside", "./file", "x//file", "/file", "file/", "x\x00y"])
def test_noncanonical_path_refuses(tmp_path, path):
    with pytest.raises(CaseError, match="normalized relative path"):
        read(tmp_path, path=path)


@pytest.mark.parametrize("field,value", [("sha256", "0" * 64), ("length", 0),
                                         ("length", True), ("length", MAX_ARTIFACT_BYTES + 1)])
def test_declared_binding_mismatch_or_invalid_length_refuses(tmp_path, field, value):
    (tmp_path / "evidence.bin").write_bytes(b"retained evidence")
    meta = metadata()
    meta[field] = value
    with pytest.raises(CaseError):
        _artifact(tmp_path, meta, "artifacts.evidence")


@pytest.mark.parametrize("kind", ["directory", "fifo", "socket", "symlink", "dangling_symlink"])
def test_actual_nonregular_files_refuse_before_read(tmp_path, kind):
    target = tmp_path / "evidence.bin"
    endpoint = None
    if kind == "directory":
        target.mkdir()
    elif kind == "fifo":
        os.mkfifo(target)
    elif kind == "socket":
        endpoint = socket.socket(socket.AF_UNIX)
        endpoint.bind(str(target))
    else:
        target.symlink_to(tmp_path / ("absent" if kind == "dangling_symlink" else "regular"))
        if kind == "symlink":
            (tmp_path / "regular").write_bytes(b"retained evidence")
    try:
        with pytest.raises(CaseError, match="regular file|symlink traversal"):
            read(tmp_path)
    finally:
        if endpoint:
            endpoint.close()


def test_root_and_intermediate_symlinks_refuse(tmp_path):
    (tmp_path / "real").mkdir()
    (tmp_path / "real/evidence.bin").write_bytes(b"retained evidence")
    (tmp_path / "link").symlink_to(tmp_path / "real", target_is_directory=True)
    with pytest.raises(CaseError, match="symlink traversal"):
        read(tmp_path / "link")
    with pytest.raises(CaseError, match="symlink traversal"):
        read(tmp_path, path="link/evidence.bin")


@pytest.mark.parametrize("replacement", ["fifo", "symlink", "regular"])
def test_leaf_replacement_between_stat_and_open_refuses(tmp_path, monkeypatch, replacement):
    leaf = tmp_path / "evidence.bin"
    leaf.write_bytes(b"retained evidence")
    (tmp_path / "other").write_bytes(b"retained evidence")
    def swap(original, name, flags, mode, dir_fd):
        if name == "evidence.bin":
            leaf.unlink()
            if replacement == "fifo":
                os.mkfifo(leaf)
            elif replacement == "symlink":
                leaf.symlink_to(tmp_path / "other")
            else:
                leaf.write_bytes(b"unselected bytes")
        return original(name, flags, mode, dir_fd=dir_fd)
    intercept_open(monkeypatch, swap)
    with pytest.raises(CaseError):
        read(tmp_path)


def test_intermediate_replacement_before_open_refuses(tmp_path, monkeypatch):
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested/evidence.bin").write_bytes(b"retained evidence")
    (tmp_path / "outside").mkdir()
    def swap(original, name, flags, mode, dir_fd):
        if name == "nested":
            (tmp_path / "nested").rename(tmp_path / "moved")
            (tmp_path / "nested").symlink_to(tmp_path / "outside", target_is_directory=True)
        return original(name, flags, mode, dir_fd=dir_fd)
    intercept_open(monkeypatch, swap)
    with pytest.raises(CaseError):
        read(tmp_path, path="nested/evidence.bin")


def test_open_directory_descriptor_survives_path_redirection(tmp_path, monkeypatch):
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested/evidence.bin").write_bytes(b"retained evidence")
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside/evidence.bin").write_bytes(b"unselected bytes")
    def swap(original, name, flags, mode, dir_fd):
        descriptor = original(name, flags, mode, dir_fd=dir_fd)
        if name == "nested":
            (tmp_path / "nested").rename(tmp_path / "moved")
            (tmp_path / "nested").symlink_to(tmp_path / "outside", target_is_directory=True)
        return descriptor
    intercept_open(monkeypatch, swap)
    assert read(tmp_path, path="nested/evidence.bin")[0] == b"retained evidence"


def test_open_file_descriptor_survives_path_redirection(tmp_path, monkeypatch):
    leaf = tmp_path / "evidence.bin"
    leaf.write_bytes(b"retained evidence")
    (tmp_path / "other").write_bytes(b"unselected bytes")
    def swap(original, name, flags, mode, dir_fd):
        descriptor = original(name, flags, mode, dir_fd=dir_fd)
        if name == "evidence.bin":
            leaf.rename(tmp_path / "moved")
            leaf.symlink_to(tmp_path / "other")
        return descriptor
    intercept_open(monkeypatch, swap)
    assert read(tmp_path)[0] == b"retained evidence"


def test_mutation_during_actual_read_refuses(tmp_path, monkeypatch):
    leaf = tmp_path / "evidence.bin"
    leaf.write_bytes(b"retained evidence")
    original = os.read
    changed = False
    def mutate(descriptor, count):
        nonlocal changed
        data = original(descriptor, count)
        if not changed:
            changed = True
            leaf.write_bytes(b"changed evidence!")
            os.utime(leaf, ns=(1, 1))
        return data
    monkeypatch.setattr(os, "read", mutate)
    with pytest.raises(CaseError, match="changed during read"):
        read(tmp_path)


def test_unsupported_capability_has_no_fallback(tmp_path, monkeypatch):
    (tmp_path / "evidence.bin").write_bytes(b"retained evidence")
    monkeypatch.delattr(os, "O_NOFOLLOW")
    with pytest.raises(CaseError, match="unsupported on this platform"):
        read(tmp_path)


@pytest.mark.parametrize("unsafe", ["sha256", "length", "fifo", "socket", "symlink"])
def test_actual_cli_refuses_with_exit2_and_no_verdict(tmp_path, unsafe):
    source = Path(__file__).parents[1] / "examples/source-coverage"
    for name in ("case.json", "source.html", "report.txt", "policy-june.json"):
        (tmp_path / name).write_bytes((source / name).read_bytes())
    endpoint = None
    if unsafe in ("sha256", "length"):
        case = json.loads((tmp_path / "case.json").read_bytes())
        case["artifacts"]["capture"][unsafe] = "0" * 64 if unsafe == "sha256" else 0
        (tmp_path / "case.json").write_text(json.dumps(case))
    else:
        leaf = tmp_path / "source.html"
        leaf.unlink()
        if unsafe == "fifo":
            os.mkfifo(leaf)
        elif unsafe == "socket":
            endpoint = socket.socket(socket.AF_UNIX)
            endpoint.bind(str(leaf))
        else:
            leaf.symlink_to(source / "source.html")
    try:
        result = subprocess.run([sys.executable, "-m", "probity_verify.cli",
                                 str(tmp_path / "case.json"), "--policy",
                                 str(tmp_path / "policy-june.json"), "--json"],
                                capture_output=True, timeout=5)
        assert result.returncode == 2
        assert result.stdout == b""
        assert result.stderr.startswith(b"probity-verify:")
    finally:
        if endpoint:
            endpoint.close()


@pytest.mark.parametrize("component", ["directory", "file"])
def test_successful_stat_then_actual_deletion_at_open_refuses(tmp_path, monkeypatch, component):
    (tmp_path / "nested").mkdir()
    leaf = tmp_path / "nested/evidence.bin"
    leaf.write_bytes(b"retained evidence")
    def remove(original, name, flags, mode, dir_fd):
        if component == "directory" and name == "nested":
            leaf.unlink()
            (tmp_path / "nested").rmdir()
        elif component == "file" and name == "evidence.bin":
            leaf.unlink()
        return original(name, flags, mode, dir_fd=dir_fd)
    intercept_open(monkeypatch, remove)
    with pytest.raises(CaseError, match="disappeared during open"):
        read(tmp_path, path="nested/evidence.bin")
