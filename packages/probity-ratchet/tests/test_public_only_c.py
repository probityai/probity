"""With the hosted referee operation unimportable (the hosted factories, the v3 driver and the countersigning
tool), the public engine imports, selects the open referee factory, decides every published v3 decision again,
and verifies a countersigned decision under both of its keys."""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BLOCKED = ("ratchet.improve.referee_live", "ratchet.improve.run_v3", "ratchet.improve.countersign")

PROGRAM = textwrap.dedent(
    """
    import importlib, importlib.abc, json, pkgutil, sys
    from pathlib import Path

    BLOCKED = tuple(sys.argv[2].split(","))

    class Refuse(importlib.abc.MetaPathFinder):
        def find_spec(self, name, path=None, target=None):
            if name in BLOCKED:
                raise ImportError(f"{name} is not part of the public engine")
            return None

    sys.meta_path.insert(0, Refuse())
    import ratchet.cli, ratchet.improve.loop, ratchet.improve.referee, ratchet.improve.referee_open
    import ratchet.demo.scenario, ratchet.agent.worker, ratchet.improve.run, ratchet.improve.run_det
    import ratchet.verify, ratchet.view, ratchet.export
    for pkg in (ratchet.verify, ratchet.view, ratchet.export):
        for mod in pkgutil.iter_modules(pkg.__path__):
            if mod.name != "__main__":
                importlib.import_module(f"{pkg.__name__}.{mod.name}")
    print("imported")

    from ratchet.improve.referee import factory_name, load_factory
    from ratchet.improve import referee_open
    assert factory_name("policy_parts", {}, {}) == "ratchet.improve.referee_open:policy_parts"
    assert load_factory(factory_name("case_suite_parts", {}, {})) is referee_open.case_suite_parts
    hosted = {"RATCHET_REFEREE_FACTORY": "hosted.mod"}
    assert factory_name("policy_parts", {}, hosted) == "hosted.mod:policy_parts"
    assert factory_name("policy_parts", {"factory": "own.mod"}, hosted) == "own.mod:policy_parts"
    print("open factory")

    from ratchet.verify import dsse
    from ratchet.verify.keys import DEFAULT_KEY_PATH, load_trusted_key
    from ratchet.verify.receipt import verify_decision
    from ratchet.verify.results import verify_results

    root = Path(sys.argv[1])
    key = load_trusted_key(DEFAULT_KEY_PATH)
    results = sorted(p for p in (root / "docs" / "results").rglob("*.dsse") if p.name != "receipt.dsse")
    receipts = sorted((root / "docs" / "results").rglob("bundles/*/receipt.dsse"))
    assert results and receipts
    for path in results:
        report = verify_results(path.read_bytes(), key, path.parent)
        assert report.ok and not report.authenticated_only, (path, report.reason)
        print("results", path.name, report.decision, len(report.verified))
    for path in receipts:
        report = verify_decision(path.read_bytes(), key)
        assert report.ok, (path, report.reason)
        print("receipt", path.parent.name, report.decision)

    # The hook example's decision admits one guard on replayed transcripts and names no evaluator, so the
    # decision verifier cannot establish it; the export's own check verifies it under the example's key.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from ratchet.export.claude_code import verify_admission
    from ratchet.improve import wire

    example = root / "examples" / "claude-code"
    example_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex((example / "public_key.txt").read_text()))
    envelope = (example / "receipt.json").read_bytes()
    harness = wire.harness(json.loads((example / "harness.json").read_text()))
    decision = verify_admission(harness, envelope, {dsse.keyid_of(example_key): example_key})
    assert decision["admitted"] is True
    assert verify_decision(envelope, example_key).reason == "payload_field_invalid:evaluator"
    print("hook example admitted")

    from ratchet.improve.receipt import Signer, countersign, verify
    from ratchet.verify.adapter import DECISION_PAYLOAD_TYPE

    run_key, pinned = Signer.generate(), Signer.generate()
    payload = dsse.parse(receipts[0].read_bytes()).payload
    signed = countersign(run_key.sign(DECISION_PAYLOAD_TYPE, payload), pinned)
    both = {run_key.keyid: run_key.public_key, pinned.keyid: pinned.public_key}
    assert verify(signed, both, threshold=2)["candidate"]
    try:
        verify(signed, {pinned.keyid: pinned.public_key}, threshold=2)
        raise AssertionError("one key passed a threshold of two")
    except ValueError:
        pass
    assert verify_decision(signed, [pinned.public_key]).ok
    assert verify_decision(signed, [run_key.public_key, pinned.public_key]).ok
    print("countersigned", len(json.loads(signed)["signatures"]))
    """
)


def test_the_engine_runs_and_verifies_every_published_decision_without_the_hosted_referee() -> None:
    out = subprocess.run(
        [sys.executable, "-c", PROGRAM, str(ROOT), ",".join(BLOCKED)],
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    assert out.returncode == 0, out.stderr
    lines = out.stdout.splitlines()
    assert lines[:2] == ["imported", "open factory"]
    assert "results v3-cell.dsse supported 1" in lines
    assert "receipt bdb5bd9b003912c4 supported" in lines
    assert "hook example admitted" in lines
    assert lines[-1] == "countersigned 2"
