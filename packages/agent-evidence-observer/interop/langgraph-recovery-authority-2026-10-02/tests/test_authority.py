"""Fresh native cases and semantic refusals after artifact reselection."""
import copy
import shutil
import sqlite3
from pathlib import Path

import pytest

from authority_common import CASES, decode, encode, sha
from authority_reader import verify_saved as read_packet
from lg_common import PacketError, withheld_for, withheld_in

RETAINED = Path(__file__).resolve().parents[1] / "retained"
WITHHELD = withheld_for(RETAINED / "WITHHELD-SOURCES.json", RETAINED / "fresh-run")


def verify_saved(root, pins):
    """Read a retained-form packet; omitted sources are those the record lists."""
    return read_packet(root, pins, WITHHELD)


@pytest.fixture(scope="module")
def packet():
    """Return the eight-case packet retained from the latest successful main run."""
    root = RETAINED / "fresh-run"
    report = decode((RETAINED / "fresh-report.json").read_bytes())
    return root, decode((root / "consumer-pins.json").read_bytes()), report


@pytest.fixture
def copied(packet, tmp_path):
    root = tmp_path / "run"
    shutil.copytree(packet[0], root)
    return root, copy.deepcopy(packet[1])


def reselect(root, pins, name, mutate):
    path = root / "attempts" / (name + ".json")
    item = decode(path.read_bytes())
    mutate(item)
    path.write_bytes(encode(item))
    path = root / "artifact-manifest.json"
    manifest = decode(path.read_bytes())
    manifest[name + ".json"] = sha((root / "attempts" / (name + ".json")).read_bytes())
    path.write_bytes(encode(manifest))
    pins["artifactManifestSha256"] = sha(path.read_bytes())


MUTATIONS = [
    ("valid-before", lambda v: v["firstProcess"].update(exitCode=False), "first-hard-exit"),
    ("valid-before", lambda v: v["secondProcess"].update(exitCode=True), "second-worker-exit"),
    ("valid-before", lambda v: v["second"].update(pid=v["first"]["pid"]), "distinct-processes"),
    ("valid-before", lambda v: v["firstProcess"].update(elapsedNs=True), "resource-elapsed"),
    ("valid-before", lambda v: v["firstProcess"].update(elapsedNs=30000000001), "resource-elapsed"),
    ("valid-before", lambda v: v["firstProcess"].update(stderrHex="00"), "worker-unexpected-output"),
    ("valid-before", lambda v: v["first"]["authority"].update(priorClock=100), "first-authority"),
    ("revoked-before", lambda v: v["second"]["authority"]["current"].update(revoked=False), "recovery-authority"),
    ("expired-before", lambda v: v["second"]["authority"]["current"].update(clock=199), "recovery-authority"),
    ("rollback-after", lambda v: v["second"]["authority"].update(priorClock=0), "recovery-authority"),
    ("valid-before", lambda v: v["second"]["authority"]["current"].update(actionSha256="0" * 64), "recovery-authority"),
    ("revoked-after", lambda v: v["second"].update(status="completed"), "recovery-disposition"),
    ("revoked-after", lambda v: v["second"].update(result={}), "refused-no-result"),
    ("revoked-after", lambda v: v["second"]["http"].append(v["first"]["http"][0]), "dispatch-population"),
    ("valid-before", lambda v: v["second"]["http"].clear(), "dispatch-population"),
    ("valid-before", lambda v: v["second"]["loaded"]["config"]["configurable"].update(checkpoint_id="other"), "reopened-checkpoint"),
    ("valid-before", lambda v: v["first"]["history"].pop(), "native-history-population"),
    ("valid-after", lambda v: v["first"]["snapshot"]["interrupts"][0]["value"].update(httpSha256="0" * 64), "reopened-checkpoint"),
    ("valid-before", lambda v: v["second"]["http"][0].update(endpoint="http://outside.example"), "http-loopback"),
    ("valid-before", lambda v: v["second"]["http"][0].update(postResponseHex="7b7d"), "http-literal-bytes"),
    ("expired-after", lambda v: v.update(finalReadbackHex="7b7d"), "readback-literal-bytes"),
    ("valid-before", lambda v: v["second"]["result"]["result"].update(revision=0), "completed-result"),
    ("valid-before", lambda v: v["second"]["history"].pop(), "completed-history-population"),
]


@pytest.mark.parametrize("name", CASES)
def test_real_authority_transition(packet, name):
    root, pins, report = packet
    assert verify_saved(root, pins) == report
    item = next(r for r in report["records"] if r["attemptId"] == name)
    assert item["freshRecoveryDispatches"] == (1 if name.startswith("valid") else 0)
    assert item["retainedNativeRevision"] == (1 if name.endswith("after") or name.startswith("valid") else 0)
    assert report["independentCustody"] == report["exactlyOnce"] == "not-established"


@pytest.mark.parametrize("name,mutate,reason", MUTATIONS)
def test_reselected_semantic_refusal(copied, name, mutate, reason):
    root, pins = copied
    reselect(root, pins, name, mutate)
    with pytest.raises(PacketError, match="^" + reason + "$"):
        verify_saved(root, pins)


@pytest.mark.parametrize("pin", ("planSha256", "artifactManifestSha256", "policySha256"))
def test_host_selection_required(copied, pin):
    root, pins = copied
    pins[pin] = "0" * 64
    with pytest.raises(PacketError, match="^consumer-" + pin + "$"):
        verify_saved(root, pins)


def test_reader_framework_sqlite_network_forbidden(packet, monkeypatch):
    import builtins
    import urllib.request
    original = builtins.__import__
    def guarded(name, *args, **kwargs):
        assert not name.startswith("langgraph")
        return original(name, *args, **kwargs)
    def forbidden(*args, **kwargs):
        raise AssertionError("reader active IO")
    monkeypatch.setattr(builtins, "__import__", guarded)
    monkeypatch.setattr(sqlite3, "connect", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    assert verify_saved(packet[0], packet[1]) == packet[2]


def test_retained_original_native_fixture_replays(tmp_path):
    import zipfile
    from pathlib import Path
    profile = Path(__file__).resolve().parents[1]
    provenance = decode((profile / "provenance.json").read_bytes())
    archive = RETAINED / "native-fixture.zip"
    assert sha(archive.read_bytes()) == provenance["archiveSha256"]
    with zipfile.ZipFile(archive) as retained:
        assert len(retained.namelist()) == provenance["memberCount"]
        assert all((tmp_path / name).resolve().is_relative_to(tmp_path.resolve()) for name in retained.namelist())
        retained.extractall(tmp_path)
    withheld = withheld_in(RETAINED / "WITHHELD-SOURCES.json", "native-fixture.zip/")
    report = read_packet(tmp_path, provenance["consumerPins"], withheld)
    assert report == decode((profile / "recorded-report.json").read_bytes())
