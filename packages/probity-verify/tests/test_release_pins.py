"""The pinned release in the docs must be the release that was published.

docs/release.json is the one record of the published files. Every page that
names the released version or its digests is checked against it, and the record
is checked against the changelog and, when asked, against PyPI itself.
"""

import json
import os
import re
import tomllib
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RELEASE = json.loads((ROOT / "docs/release.json").read_text(encoding="utf-8"))
VERSION = RELEASE["version"]
PAGES = ("README.md", "docs/install.md", "docs/recipes.md")
DIGEST = re.compile(r"\b[0-9a-f]{64}\b")


def _tuple(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def _text(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def test_release_is_the_latest_dated_changelog_section():
    dated = re.findall(r"^## (\d+\.\d+\.\d+) \(\d{4}-\d{2}-\d{2}\)$", _text("CHANGELOG.md"), re.MULTILINE)
    assert dated, "the changelog lists no dated release"
    assert max(dated, key=_tuple) == VERSION, (
        "docs/release.json names a release other than the newest dated changelog entry; "
        "after publishing, update it from PyPI's file list")


def test_release_does_not_outrun_the_source_version():
    source = tomllib.loads(_text("pyproject.toml"))["project"]["version"]
    assert _tuple(VERSION) <= _tuple(source)


def test_release_files_are_named_for_the_version():
    names = {item["name"] for item in RELEASE["files"]}
    assert names == {f"probity_verify-{VERSION}-py3-none-any.whl", f"probity_verify-{VERSION}.tar.gz"}
    assert RELEASE["tag"] == f"probity-verify-v{VERSION}"
    for item in RELEASE["files"]:
        assert DIGEST.fullmatch(item["sha256"])


@pytest.mark.parametrize("page", PAGES)
def test_pages_name_only_the_released_version(page):
    text = _text(page)
    pinned = set(re.findall(r"probity-verify==(\d+\.\d+\.\d+)", text))
    wheels = set(re.findall(r"probity_verify-(\d+\.\d+\.\d+)(?:-py3|\.tar)", text))
    stated = set(re.findall(r"\bVersion (\d+\.\d+\.\d+)\b", text))
    assert (pinned | wheels | stated) <= {VERSION}, f"{page} names another version"


def test_install_page_carries_the_release_digests_and_commit():
    text = _text("docs/install.md")
    assert f"probity-verify=={VERSION}" in text
    assert RELEASE["commit"] in text and RELEASE["tag"] in text
    digests = {item["sha256"] for item in RELEASE["files"]}
    assert set(DIGEST.findall(text)) == digests
    for item in RELEASE["files"]:
        assert item["name"] in text


def test_release_guide_names_the_released_wheel():
    assert f"probity_verify-{VERSION}-py3-none-any.whl" in _text("docs/RELEASING.md")


def test_agent_card_reports_the_installed_version():
    pytest.importorskip("a2a")
    from importlib.metadata import version

    from probity_verify.a2a_server import _package_version
    assert _package_version() == version("probity-verify")


@pytest.mark.skipif(os.environ.get("PROBITY_VERIFY_ONLINE") != "1",
                    reason="set PROBITY_VERIFY_ONLINE=1 to compare against PyPI")
def test_release_record_matches_pypi():
    url = f"https://pypi.org/pypi/probity-verify/{VERSION}/json"
    with urllib.request.urlopen(url, timeout=30) as response:
        published = json.load(response)
    remote = {item["filename"]: item["digests"]["sha256"] for item in published["urls"]}
    assert remote == {item["name"]: item["sha256"] for item in RELEASE["files"]}
