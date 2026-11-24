"""Build the web_bot_auth/v1 cases signed in the agent browser profile.

Every request is signed the way a signing browser proxy signs what an agent's browser sends: label ``agent``, tag
``web-bot-auth``, the covered components ``@method @target-uri @authority content-digest probity-stamp-digest`` and
the ``signature-agent`` member ``agent``, with ``created``, ``expires`` (60 s later), ``nonce``, ``keyid`` (the RFC
7638 thumbprint) and ``alg="ed25519"``. ``Probity-Stamp-Digest`` is an RFC 8941 String holding the stamp digest of
the request's verified principals, so the request names its release record without naming the user.

The signature base is written here by hand from the component list, so no verifier is the oracle for a request it
judges. The keys come from fixed public labels, so the bytes are the same on every run and carry no trust outside
this corpus. ``python3 gen_vectors.py`` writes the cases; ``--check`` compares them with the committed bytes.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from dataclasses import dataclass, field, replace
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parent
SUITE = "web-bot-auth-browser-profile/v1"
AGENT = "https://agent.example/.well-known/http-message-signatures-directory"
AUTHORITY = "mail.example"
LABEL = "agent"
CREATED = 1795435200  # 2026-11-23T12:00:00Z
TTL = 60
AT = "2026-11-23T12:00:10Z"
STAMP = "sha256:" + hashlib.sha256(b"principals of the release record").hexdigest()
OTHER_STAMP = "sha256:" + hashlib.sha256(b"principals of another release record").hexdigest()
COVERED = ("@method", "@target-uri", "@authority", "content-digest", "probity-stamp-digest")
#: What a consumer of the profile requires: every covered component, sorted as the policy wants them.
REQUIRED = sorted([*COVERED, "signature-agent"])


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _key(label: bytes) -> tuple[Ed25519PrivateKey, dict[str, str]]:
    private = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label).digest())
    x = _b64url(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    required = json.dumps({"crv": "Ed25519", "kty": "OKP", "x": x}, separators=(",", ":"), sort_keys=True)
    return private, {"kty": "OKP", "crv": "Ed25519", "x": x, "kid": _b64url(hashlib.sha256(required.encode()).digest()),
                     "use": "sig"}


AGENT_KEY, AGENT_JWK = _key(b"web-bot-auth browser profile: the agent key")
STRAY_KEY, STRAY_JWK = _key(b"web-bot-auth browser profile: a key no directory lists")


def _sf_string(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _content_digest(body: bytes) -> str:
    return f"sha-256=:{base64.b64encode(hashlib.sha256(body).digest()).decode('ascii')}:"


def _authority(url: str) -> str:
    return url.split("/", 3)[2]


@dataclass(frozen=True)
class Signed:
    """One request as the proxy signs it, then what an on-path party or a stale clock does to it."""

    method: str
    url: str
    body: bytes
    stamp: str = STAMP
    covered: tuple[str, ...] = COVERED
    created: int = CREATED
    ttl: int = TTL
    key: Ed25519PrivateKey = field(default=AGENT_KEY, repr=False)
    keyid: str = AGENT_JWK["kid"]
    nonce: str = "browser-0001"
    #: Header values replaced after signing (None drops the header), and the body the receiver got.
    sent: tuple[tuple[str, str | None], ...] = ()
    received_body: bytes | None = None

    def request(self) -> dict:
        values = {"@method": self.method, "@target-uri": self.url, "@authority": _authority(self.url),
                  "content-digest": _content_digest(self.body), "probity-stamp-digest": _sf_string(self.stamp)}
        identifiers = [_sf_string(c) for c in self.covered] + [f'"signature-agent";key="{LABEL}"']
        params = (f"({' '.join(identifiers)});created={self.created};expires={self.created + self.ttl};"
                  f'nonce="{self.nonce}";keyid="{self.keyid}";alg="ed25519";tag="web-bot-auth"')
        lines = [f"{_sf_string(c)}: {values[c]}" for c in self.covered]
        lines += [f'"signature-agent";key="{LABEL}": {_sf_string(AGENT)}', f'"@signature-params": {params}']
        signature = base64.b64encode(self.key.sign("\n".join(lines).encode("ascii"))).decode("ascii")
        headers: dict[str, str | None] = {
            "Host": _authority(self.url), "Accept-Encoding": "identity",
            "Signature-Agent": f"{LABEL}={_sf_string(AGENT)}", "Content-Digest": values["content-digest"],
            "Probity-Stamp-Digest": values["probity-stamp-digest"],
            "Signature-Input": f"{LABEL}={params}", "Signature": f"{LABEL}=:{signature}:",
        }
        if self.body:
            headers = {**headers, "Content-Type": "application/json", "Content-Length": str(len(self.body))}
        headers.update(dict(self.sent))
        return {"method": self.method, "url": self.url,
                "headers": [[name, value] for name, value in headers.items() if value is not None]}


POST = Signed("POST", "https://mail.example/api/drafts?folder=outbox", b'{"to":"ops@example.org","subject":"weekly"}')
GET = Signed("GET", "https://mail.example/inbox?page=2", b"")


@dataclass(frozen=True)
class Case:
    name: str
    signed: Signed
    decision: str
    reason: str
    note: str
    at: str = AT
    pin: str | None = STAMP
    required: tuple[str, ...] = tuple(REQUIRED)
    directory: tuple[dict[str, str], ...] = (AGENT_JWK,)


CASES = (
    Case("supported", POST, "supported", "request_signed_by_pinned_agent",
         "A POST signed in the profile, its body and the release record's stamp digest as they were sent."),
    Case("supported-get-empty-body", GET, "supported", "request_signed_by_pinned_agent",
         "A GET covers the digest of no bytes; the consumer binds the empty body, else the body is not established."),
    Case("body-swapped", replace(POST, received_body=b'{"to":"attacker@example.net","subject":"weekly"}'),
         "contradicted", "content_digest_mismatch",
         "An on-path party replaced the body; the covered Content-Digest names the body that was signed."),
    Case("digest-dropped", replace(POST, sent=(("Content-Digest", None),)), "contradicted", "content_digest_mismatch",
         "An on-path party dropped Content-Digest; the signature still lists it, so the body is bound to nothing."),
    Case("digest-not-covered", replace(POST, covered=tuple(c for c in COVERED if c != "content-digest")),
         "contradicted", "component_not_covered",
         "A signature that leaves content-digest out is not the profile, whatever else it covers."),
    Case("stale", POST, "contradicted", "signature_expired",
         "Two minutes after created, past the 60 s the profile signs for.", at="2026-11-23T12:02:00Z"),
    Case("ttl-over-profile", replace(POST, ttl=300), "contradicted", "validity_window_too_long",
         "A signature valid for 300 s is longer than the 60 s the profile allows."),
    Case("key-not-in-directory", replace(POST, key=STRAY_KEY, keyid=STRAY_JWK["kid"]),
         "not_established", "key_not_in_directory",
         "Signed by a key the pinned directory does not list: a stale pin, not a forgery finding."),
    Case("path-required", POST, "contradicted", "component_not_covered",
         "A consumer that requires @path refuses the profile, which covers the path through @target-uri.",
         required=tuple(sorted([*REQUIRED, "@path"]))),
    Case("stamp-digest-swapped", replace(POST, sent=(("Probity-Stamp-Digest", _sf_string(OTHER_STAMP)),)),
         "contradicted", "pinned_field_mismatch",
         "An on-path party replaced the stamp digest; the consumer pins the one its release record names."),
    Case("stamp-digest-swapped-unpinned", replace(POST, sent=(("Probity-Stamp-Digest", _sf_string(OTHER_STAMP)),)),
         "contradicted", "signature_invalid",
         "The same swap, read by a consumer that holds no release record: the signature covers the field.",
         pin=None),
    Case("stamp-digest-of-another-release", replace(POST, stamp=OTHER_STAMP), "contradicted", "pinned_field_mismatch",
         "A request validly signed for another release: only the pinned stamp digest tells them apart."),
)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _files(case: Case) -> dict[str, bytes]:
    request = _json(case.signed.request())
    body = case.signed.body if case.signed.received_body is None else case.signed.received_body
    directory = _json({"keys": list(case.directory)})
    case_id = f"web-bot-auth-browser-{case.name}"
    artifacts = {name: {"path": name, "length": len(data), "sha256": _digest(data)}
                 for name, data in (("request.json", request), ("body.bin", body), ("directory.json", directory))}
    assessment: dict[str, object] = {
        "claim_type": "web_bot_auth/v1", "request": "request.json", "body": "body.bin", "directory": "directory.json",
        "directory_sha256": _digest(directory), "signature_agent": AGENT, "authority": AUTHORITY, "at": case.at,
        "label": LABEL, "required_components": list(case.required), "max_age_seconds": TTL,
        "max_validity_seconds": TTL,
    }
    if case.pin is not None:
        assessment["pinned_fields"] = {"probity-stamp-digest": _sf_string(case.pin)}
    return {
        "case.json": _json({"schema_version": "probity-case/v1", "case_id": case_id, "artifacts": artifacts}),
        "policy.json": _json({"schema_version": "probity-policy/v1", "assessments": {case_id: assessment}}),
        "request.json": request, "body.bin": body, "directory.json": directory,
    }


def build() -> dict[str, bytes]:
    """Every corpus file, by its path under the corpus root."""
    out: dict[str, bytes] = {}
    entries = []
    for case in CASES:
        files = _files(case)
        out.update({f"cases/{case.name}/{name}": data for name, data in files.items()})
        entries.append({"id": case.name, "path": f"cases/{case.name}", "note": case.note,
                        "files": {name: _digest(data) for name, data in sorted(files.items())},
                        "expected": {"decision": case.decision, "reason": case.reason}})
    manifest: dict[str, object] = {"suite": SUITE, "vectors": entries,
                                   "verifierContract": "agent-evidence-verify case.json --policy policy.json --json"}
    manifest["corpusDigest"] = _digest(_json(entries))
    out["MANIFEST.json"] = _json(manifest)
    return out


def generate(root: Path = ROOT) -> None:
    """Write the corpus under ``root``."""
    for path, data in build().items():
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_bytes(data)


def stale(root: Path = ROOT) -> list[str]:
    """The corpus files under ``root`` that are missing, changed or not generated."""
    expected = build()
    present = {p.relative_to(root).as_posix() for p in [root / "MANIFEST.json", *(root / "cases").rglob("*")]
               if p.is_file()} if (root / "cases").is_dir() else set()
    changed = [p for p, data in expected.items() if not (root / p).is_file() or (root / p).read_bytes() != data]
    return sorted(set(changed) | (present - set(expected)))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="compare the committed corpus with a fresh build")
    if parser.parse_args().check:
        problems = stale()
        for problem in problems:
            print(f"stale: {problem}")
        print(f"{len(CASES)} cases, {len(problems)} stale files")
        sys.exit(1 if problems else 0)
    generate()
