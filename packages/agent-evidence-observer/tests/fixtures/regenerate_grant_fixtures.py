"""Regenerate the two observer fixtures that sign fresh grants, in the one grant model, from fixed seeds.

Usage: python3 gen_declaration_fixtures.py <worktree>. Writes declaration-reference/grant.json and
declaration-demo/action-inputs.json (grant, policy, outside-catalog grant), then re-hashes
declaration-demo/file-manifest.json. The retained native packet in action-inputs.json is left as it was recorded.
"""
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from probity_records import Signer
from probity_records.grants import raw_public
from probity_records.possession import cnf_for_signer

from probity_observer.exact_grant import ActionRequest, issue_exact_grant


def signer(label: str) -> Signer:
    return Signer(Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest()))


def grant(issuer: Signer, holder: Signer, request: dict, not_before: str, expires_at: str) -> dict:
    return issue_exact_grant(issuer, ActionRequest(**request), holder_key=raw_public(holder), cnf=cnf_for_signer(holder),
                             not_before=not_before, expires_at=expires_at)


def main(root: Path) -> None:
    records = root / "packages/agent-evidence-observer/tests/fixtures/records"
    issuer = signer("probity observer fixture issuer v1")
    holder = signer("probity observer fixture holder v1")
    issuer_hex = issuer.public.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    ref = records / "declaration-reference/grant.json"
    old = json.loads(ref.read_bytes())
    request = old["grant"]["request"]
    out = {"grant": [grant(issuer, holder, request, "2026-10-01T00:00:00Z", "2026-10-01T00:05:00Z")],
           "issuerKey": issuer_hex, "referenceTime": old["referenceTime"]}
    ref.write_text(json.dumps(out, separators=(",", ":"), sort_keys=True))

    demo = records / "declaration-demo"
    path = demo / "action-inputs.json"
    inputs = json.loads(path.read_bytes())
    start = inputs["grant"]["issuedAt"]
    end = inputs["grant"]["expiresAt"]
    inputs["grant"] = [grant(issuer, holder, inputs["request"], start, end)]
    inputs["outsideCatalogGrant"] = [grant(issuer, holder, inputs["outsideCatalogRequest"], start, end)]
    inputs["grantPolicy"] = {"issuer_key": issuer_hex, "max_validity_seconds": 300}
    path.write_text(json.dumps(inputs, indent=2, sort_keys=True) + "\n")

    manifest = demo / "file-manifest.json"
    files = {p.relative_to(demo).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in sorted(demo.rglob("*")) if p.is_file() and p.name != "file-manifest.json"}
    current = json.loads(manifest.read_bytes())
    assert set(current["fileSha256"]) == set(files), "the demo file list changed"
    raw = manifest.read_bytes()
    manifest.write_text(json.dumps({"fileSha256": files}, indent=2, sort_keys=True) + ("\n" if raw.endswith(b"\n") else ""))


if __name__ == "__main__":
    main(Path(sys.argv[1]))
