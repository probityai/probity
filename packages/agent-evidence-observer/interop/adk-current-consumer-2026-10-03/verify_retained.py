"""Replay the retained current-ADK packet with public code and compare the retained results.

Exit 0 only when the retained host policy matches its pin, the retained source population
(files kept plus the digests of the withheld files) matches the selection recorded before
the run, the public reader reproduces the retained report bytes, and the retained
publication receipt names the reader output (the report plus one newline). No producer runs.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
PACKAGE = HERE.parent.parent
sys.path[:0] = [
    str(PACKAGE / "src"),
    str(PACKAGE / "interop" / "adk-ticket-2026-10-02" / "src"),
]

from probity_adk.contract import decode, encode, sha, withheld_for  # noqa: E402
from probity_adk.reader import verify_saved  # noqa: E402

RETAINED = HERE / "retained"
RUN = RETAINED / "fresh-current-run"
PACKET = RUN / "packet"
# Host-selected pin for retained/fresh-current-run/host-policy.json (original CI run).
POLICY_SHA256 = "277f5f57c44c95d5ebfae3624d43f49dbfd907931638e10f658a41151332268e"


def read_json(path: Path) -> Any:
    """Decode one retained JSON file."""
    return decode(path.read_bytes())


def blob(raw: bytes) -> str:
    """Git blob identity of one native SDK source file."""
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def selected_pins(policy: dict[str, Any]) -> dict[str, Any]:
    """Recompute the host pins from retained packet bytes."""
    return {
        "profile": "probity-google-adk-ticket-v0",
        "planSha256": sha((PACKET / "plan-before-run.json").read_bytes()),
        "sourceManifestSha256": sha(
            (PACKET / "source-manifest-before-run.json").read_bytes()
        ),
        "artifactManifestSha256": sha(
            (PACKET / "artifact-manifest.json").read_bytes()
        ),
        "consumerTime": policy["consumerTime"],
    }


def source_digests(withheld: dict[str, str]) -> dict[str, str]:
    """Digest every kept source file and add the withheld digests."""
    kept = {
        p.relative_to(PACKET / "sources").as_posix(): sha(p.read_bytes())
        for p in (PACKET / "sources").rglob("*")
        if p.is_file()
    }
    return {**kept, **{k.removeprefix("sources/"): d for k, d in withheld.items()}}


def check_population(withheld: dict[str, str]) -> str | None:
    """Return a refusal when the packet sources differ from the recorded selection."""
    observed = source_digests(withheld)
    if observed != read_json(PACKET / "source-manifest-before-run.json"):
        return "retained source population differs from the manifest"
    modules = {
        ("probity_observer/" if k.startswith("observer/") else "probity_adk/")
        + k.split("/", 1)[1]: d
        for k, d in observed.items()
        if k.startswith(("observer/", "adapter/")) and k.endswith(".py")
    }
    if modules != read_json(HERE / "installation-policy.json")["modules"]:
        return "retained reader sources differ from the installation policy"
    native = {
        k[4:]: blob((PACKET / "sources" / k).read_bytes())
        for k in observed
        if k.startswith("adk/") and k.endswith(".py")
    }
    if native != read_json(HERE / "native-source-selection.json")["pythonGitBlobs"]:
        return "retained SDK sources differ from the native source selection"
    return None


def main() -> int:
    """Return 0 when the retained packet replays to the retained report bytes."""
    raw = (RUN / "host-policy.json").read_bytes()
    if sha(raw) != POLICY_SHA256:
        print("retained host policy differs from the selected pin", file=sys.stderr)
        return 1
    policy = decode(raw)
    pins = selected_pins(policy)
    if {k: policy[k] for k in pins} != pins:
        print("retained host policy differs from the packet", file=sys.stderr)
        return 1
    withheld = withheld_for(RETAINED / "WITHHELD-SOURCES.json", PACKET)
    refusal = check_population(withheld)
    if refusal:
        print(refusal, file=sys.stderr)
        return 1
    report = encode(verify_saved(PACKET, pins, withheld))
    if report != (PACKET / "report.json").read_bytes():
        print("replayed report differs from the retained report", file=sys.stderr)
        return 1
    receipt = read_json(RUN / "publication" / "publication-receipt.json")
    if receipt["readerReportSha256"] != sha(report + b"\n"):
        print("publication receipt names a different report", file=sys.stderr)
        return 1
    print("current ADK retained packet verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
