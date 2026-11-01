"""The host-side reads the observer image runs, against directory trees laid out as overlay layers."""

from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.util
from pathlib import Path

from probity_observer.done.basharena import episode

_loader = importlib.machinery.SourceFileLoader("observer_tools", str(episode.resource("observer_tools.txt")))
_spec = importlib.util.spec_from_loader("observer_tools", _loader)
tools = importlib.util.module_from_spec(_spec)
_loader.exec_module(tools)

CURL = b"\x7fELF curl 7.81"


def _md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()  # noqa: S324 - dpkg's own md5sums format


def _layer(root: Path, files: dict[str, bytes]) -> Path:
    for rel, data in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return root


def _image(tmp_path: Path) -> list[str]:
    base = _layer(tmp_path / "base", {"usr/bin/curl": CURL,
                                      "var/lib/dpkg/info/curl.md5sums": f"{_md5(CURL)}  usr/bin/curl\n".encode()})
    return [str(_layer(tmp_path / "top", {"etc/motd": b"hi"})), str(base)]


def test_a_binary_replaced_with_its_container_sums_rewritten_does_not_match(tmp_path):
    fake = b"#!/bin/sh\necho curl 7.99\n"
    root = _layer(tmp_path / "root", {"usr/bin/curl": fake,
                                      "var/lib/dpkg/info/curl.md5sums": f"{_md5(fake)}  usr/bin/curl\n".encode()})
    sums = tools.image_sums(_image(tmp_path))
    assert tools.match_sums(str(root), sums, ["/usr/bin/curl"]) == {"/usr/bin/curl": False}


def test_a_binary_rewritten_with_its_own_bytes_matches_the_image_sums(tmp_path):
    root = _layer(tmp_path / "root", {"usr/bin/curl": CURL})
    sums = tools.image_sums(_image(tmp_path))
    assert tools.match_sums(str(root), sums, ["/usr/bin/curl", "/usr/bin/absent"]) == {
        "/usr/bin/curl": True, "/usr/bin/absent": False}


def test_the_topmost_layer_holding_a_package_sums_file_wins(tmp_path):
    newer = b"\x7fELF curl 7.82"
    layers = _image(tmp_path)
    _layer(Path(layers[0]), {"var/lib/dpkg/info/curl.md5sums": f"{_md5(newer)}  usr/bin/curl\n".encode()})
    assert tools.image_sums(layers) == {"/usr/bin/curl": {_md5(newer)}}


def test_a_path_two_packages_list_matches_either_sum(tmp_path):
    other = b"\x7fELF curl from another package"
    layer = _layer(tmp_path / "base", {"var/lib/dpkg/info/a.md5sums": f"{_md5(CURL)}  usr/bin/curl\n".encode(),
                                       "var/lib/dpkg/info/b.md5sums": f"{_md5(other)}  usr/bin/curl\n".encode()})
    root = _layer(tmp_path / "root", {"usr/bin/curl": CURL})
    assert tools.match_sums(str(root), tools.image_sums([str(layer)]), ["/usr/bin/curl"]) == {"/usr/bin/curl": True}


def test_a_package_the_image_deleted_has_no_sums(tmp_path, monkeypatch):
    layers = _image(tmp_path)
    _layer(Path(layers[0]), {"var/lib/dpkg/info/curl.md5sums": f"{_md5(b'x')}  usr/bin/curl\n".encode()})
    monkeypatch.setattr(tools, "_whiteout", lambda path: path.startswith(layers[0]))
    assert tools.image_sums(layers) == {}
