"""The observer side of the parent-directory pytest configuration fix: which files it copies out,
what it records about them, and what the docker backend refuses to read back."""
from __future__ import annotations

import hashlib
import sys

import pytest

from probity_observer import record_oe
from probity_observer.launch import backend_docker
from probity_observer.sensors import strace

SECTIONLESS = b'[project]\nname = "x"\nversion = "0"\n'
SECTIONED = b'[project]\nname = "x"\n\n[tool.pytest.ini_options]\naddopts = "-p no:x"\n'
DIGEST = hashlib.sha256(SECTIONLESS).hexdigest()


@pytest.mark.parametrize("name,data,section", [
    ("/pyproject.toml", SECTIONLESS, False), ("/pyproject.toml", SECTIONED, True),
    ("/pyproject.toml", b"[tool.pytest]\nminversion = '9'\n", True),
    ("/tox.ini", b"[tox]\nenvlist = py\n", False), ("/tox.ini", b"[pytest]\naddopts = -q\n", True),
    ("/setup.cfg", b"[metadata]\nname = x\n", False), ("/setup.cfg", b"[tool:pytest]\naddopts = -q\n", True),
    ("/pyproject.toml", b"not = [toml", True), ("/setup.cfg", b"\xff\xfe", True),
])
def test_observer_pytest_section(name, data, section):
    assert record_oe.pytest_section(name, data) is section


def test_observer_records_the_facts_for_an_ancestor_write_when_it_has_a_reader():
    event = strace.Event(kind="write", pid=1, time=0.0, path="/home/agent/pyproject.toml")
    files = {"/home/agent/pyproject.toml": SECTIONLESS}
    facts = record_oe.ancestor_config_facts(event, "/home/agent/workspace", files.get)
    assert facts == {"content_sha256": DIGEST, "pytest_section": False}
    assert record_oe.ancestor_config_facts(event, "/home/agent/workspace", None) == {}
    assert record_oe.ancestor_config_facts(event, "/srv/other/workspace", files.get) == {}
    entry = record_oe._external(event, "/home/agent/workspace", files.get)
    assert entry["pytest_section"] is False and entry["content_sha256"] == DIGEST
    assert "pytest_section" not in record_oe._external(event, "/home/agent/workspace")


def event(kind, path):
    return strace.Event(kind=kind, pid=1, time=0.0, path=path)


def test_paths_to_copy_out_are_ancestor_writes_of_the_three_files_once():
    events = [event("write", "/pyproject.toml"), event("write", "/pyproject.toml"),
              event("create", "/home/agent/tox.ini"), event("write", "/home/other/setup.cfg"),
              event("write", "/home/agent/workspace/setup.cfg"), event("write", "/conftest.py"),
              event("unlink", "/setup.cfg"), event("write", "/home/agent/notes.txt")]
    assert record_oe.ancestor_config_paths(events, "/home/agent/workspace") == [
        "/pyproject.toml", "/home/agent/tox.ini"]
    assert record_oe.ancestor_config_paths(events, "/workspace") == ["/pyproject.toml"]


def fake_docker(tmp_path, body):
    script = tmp_path / "docker"
    script.write_text(f"#!{sys.executable}\nimport os, shutil, sys\n{body}\n")
    script.chmod(0o755)
    return str(script)


COPY = ("src, dest = sys.argv[2], sys.argv[3]\n"
        "shutil.copy(os.environ['FAKE_SOURCE'], dest) if os.environ.get('FAKE_SOURCE') "
        "else sys.exit(1)\n")


def test_collect_outside_reads_a_regular_file(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.write_bytes(SECTIONLESS)
    monkeypatch.setenv("FAKE_SOURCE", str(source))
    docker = fake_docker(tmp_path, COPY)
    got = backend_docker.collect_outside("c", ["/pyproject.toml"], tmp_path / "out", docker)
    assert got == {"/pyproject.toml": SECTIONLESS}


def test_collect_outside_leaves_out_a_failed_copy(tmp_path, monkeypatch):
    monkeypatch.delenv("FAKE_SOURCE", raising=False)
    docker = fake_docker(tmp_path, COPY)
    assert backend_docker.collect_outside("c", ["/pyproject.toml"], tmp_path / "out",
                                          docker) == {}


def test_collect_outside_never_follows_a_symbolic_link(tmp_path):
    secret = tmp_path / "secret"
    secret.write_bytes(b"host secret")
    docker = fake_docker(tmp_path, f"os.symlink({str(secret)!r}, sys.argv[3])")
    assert backend_docker.collect_outside("c", ["/pyproject.toml"], tmp_path / "out",
                                          docker) == {}


def test_collect_outside_refuses_an_oversized_file(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.write_bytes(b"x" * (backend_docker.MAX_OUTSIDE_BYTES + 1))
    monkeypatch.setenv("FAKE_SOURCE", str(source))
    docker = fake_docker(tmp_path, COPY)
    assert backend_docker.collect_outside("c", ["/pyproject.toml"], tmp_path / "out",
                                          docker) == {}


def test_collect_outside_with_no_paths_makes_nothing(tmp_path):
    assert backend_docker.collect_outside("c", [], tmp_path / "out") == {}
    assert not (tmp_path / "out").exists()


def test_the_container_is_kept_so_its_files_can_be_copied_out():
    identity = backend_docker.Identity("img", "sha256:abc", "strace -- version 6.6", "27")
    argv = backend_docker.command(identity, name="n", workspace="/w", agent_argv=["true"],
                                  env={}, uid=1000, network=False)
    assert "--rm" not in argv
