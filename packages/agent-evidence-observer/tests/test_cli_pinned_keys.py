"""The verify command trusts only keys pinned on its command line."""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

import pytest

from probity_observer.cli import main
from probity_observer.crypto import SigningKey, VerificationError, canonical, digest, strict_loads
from probity_observer.records import tree_root

PACKET = Path(__file__).resolve().parents[1] / "scripts" / "fixtures" / "broker-packet"
OBSERVER_KEY = "a592976c199b8a4f3a80ca4412df916de591aa4a10f95e0b8030e1321bd2d9de"
WITNESS_KEY = "143f322c613549cf4da40ae09b0634f82b68d2d5a1017639bdde2e1eb15353f6"


def pins(observer: str = OBSERVER_KEY, witness: str = WITNESS_KEY) -> list[str]:
    return ["--observer-key", observer, "--witness-key", witness]


def forge(root: Path, observer: SigningKey, witness: SigningKey) -> None:
    """Change the retained write and re-sign every signature under fresh keys."""
    packet = strict_loads((root / "packet.json").read_bytes())
    entries = [strict_loads(line) for line in (root / "history.jsonl").read_bytes().splitlines()]
    result = root / "workspace" / "result.txt"
    result.write_text("forged content\n")
    after_root = tree_root(root / "workspace")
    claim = packet["claim"]
    write = claim["writes"][0]
    write["contentDigest"] = hashlib.sha256(result.read_bytes()).hexdigest()
    write["afterRoot"] = after_root
    claim["afterRoot"] = after_root
    commitment = packet["commitment"]
    commitment["keyid"] = observer.public_hex
    payload = {"preimage": commitment["preimage"], "committedAt": commitment["committedAt"]}
    commitment["signature"] = observer.sign("probity-prior-commitment-v0", payload)
    packet["claimKeyid"] = observer.public_hex
    packet["claimSignature"] = observer.sign("probity-claim-v0", claim)
    events = [entry["event"] for entry in entries]
    events[0]["commitment"] = commitment
    events[0]["commitmentDigest"] = digest("probity-prior-commitment-v0", payload)
    for event in events:
        if event["kind"] in {"write-intent", "write"}:
            event["contentDigest"] = write["contentDigest"]
            if event["kind"] == "write":
                event["afterRoot"] = after_root
    events[-1]["claimDigest"] = digest("probity-claim-v0", claim)
    rebuilt, previous = [], "0" * 64
    for index, event in enumerate(events, start=1):
        body = {"sequence": index, "previous": previous, "event": event}
        rebuilt.append({**body, "hash": digest("probity-history-entry-v0", body)})
        previous = rebuilt[-1]["hash"]
    (root / "history.jsonl").write_bytes(b"".join(canonical(e) + b"\n" for e in rebuilt))

    def checkpoint(prefix: list[dict]) -> dict:
        body = {"count": len(prefix), "head": prefix[-1]["hash"]}
        return {**body, "keyid": witness.public_hex, "signature": witness.sign("probity-checkpoint-v0", body)}

    packet["startCheckpoint"] = checkpoint(rebuilt[:1])
    packet["checkpoint"] = checkpoint(rebuilt)
    (root / "packet.json").write_bytes(canonical(packet))
    (root / "trusted-keys.json").write_bytes(
        canonical({"observer": observer.public_hex, "witness": witness.public_hex})
    )


def test_retained_packet_verifies_under_the_pinned_keys(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["verify", str(PACKET), *pins()]) == 0
    assert '"status": "verified"' in capsys.readouterr().out


def test_packet_ships_no_keys() -> None:
    assert not (PACKET / "trusted-keys.json").exists()


@pytest.mark.parametrize("given", [[], ["--observer-key", OBSERVER_KEY], ["--witness-key", WITNESS_KEY]])
def test_verify_refuses_without_both_pins(given: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as stopped:
        main(["verify", str(PACKET), *given])
    assert stopped.value.code == 2
    assert "verified" not in capsys.readouterr().out


def test_packet_resigned_under_fresh_keys_is_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = tmp_path / "forged"
    shutil.copytree(PACKET, root)
    observer, witness = SigningKey.generate(), SigningKey.generate()
    forge(root, observer, witness)
    # The forgery is internally consistent: it verifies under the forger's own keys.
    assert main(["verify", str(root), *pins(observer.public_hex, witness.public_hex)]) == 0
    capsys.readouterr()
    # Against the independently pinned keys it never prints a verified line.
    with pytest.raises(VerificationError, match="pinned observer key"):
        main(["verify", str(root), *pins()])
    assert "verified" not in capsys.readouterr().out
