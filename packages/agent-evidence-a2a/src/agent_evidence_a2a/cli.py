"""Command line: verify one card, probe an endpoint's TLS posture, score verifiers on the corpora."""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from collections.abc import Callable, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from agent_evidence_a2a.corpus import default_verifier, score_card_verifier, score_ssrf_judge
from agent_evidence_a2a.ssrf import recorded_judge
from agent_evidence_a2a.transport import probe
from agent_evidence_a2a.trust import TrustStore
from agent_evidence_a2a.vectors import check_canonicaliser, reference_canonicalize
from agent_evidence_a2a.verify import verify_served_card


def _load(spec: str) -> Callable[..., Any]:
    module, _, name = spec.partition(":")
    target: Callable[..., Any] = getattr(importlib.import_module(module), name)
    return target


def _verify(args: argparse.Namespace) -> int:
    trust = TrustStore.from_file(args.trust)
    now = datetime.fromisoformat(args.now) if args.now else None
    verdict = verify_served_card(Path(args.card).read_bytes(), trust, now=now)
    print(json.dumps({"accepted": verdict.accepted, "findings": [f.__dict__ for f in verdict.findings]}, indent=1))
    return 0 if verdict.accepted else 1


def _tls(args: argparse.Namespace) -> int:
    reports = [probe(url, allow_local=args.allow_local) for url in args.url]
    print(json.dumps([r.to_json() for r in reports], indent=1))
    return 0 if all(r.passed for r in reports) else 1


def _corpus(args: argparse.Namespace) -> int:
    report = score_card_verifier(_load(args.verifier) if args.verifier else default_verifier())
    print(
        json.dumps(
            {
                "detected": len(report.detected),
                "missed": list(report.missed),
                "false_rejects": list(report.false_rejects),
                "pending": list(report.pending),
            },
            indent=1,
        )
    )
    return 0 if report.ok else 1


def _canonicaliser(args: argparse.Namespace) -> int:
    impl = _load(args.impl) if args.impl else reference_canonicalize
    report = check_canonicaliser(impl, _load(args.signing) if args.signing else None)
    print(json.dumps({"total": report.total, "passed": report.passed, "failed": list(report.failed_ids)}, indent=1))
    return 0 if not report.failed_ids else 1


def _ssrf(args: argparse.Namespace) -> int:
    report = score_ssrf_judge(_load(args.judge) if args.judge else recorded_judge())
    print(
        json.dumps(
            {"caught": len(report.caught), "missed": list(report.missed), "false_flags": list(report.false_flags)},
            indent=1,
        )
    )
    return 0 if report.ok else 1


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point; exit status 1 when a card is rejected, a posture does not pass, or a score is not clean."""
    parser = argparse.ArgumentParser(prog="agent-evidence-a2a", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify", help="verify a served card file against a trust store")
    verify.add_argument("card")
    verify.add_argument("--trust", required=True)
    verify.add_argument("--now", help="ISO 8601 clock; defaults to the current time")
    verify.set_defaults(run=_verify)
    tls = sub.add_parser(
        "tls",
        help="judge AUTH-TLS-001, AUTH-TLS-002 and AUTH-SERVER-001 for each endpoint URL (exit 1 unless all pass)",
    )
    tls.add_argument("url", nargs="+")
    tls.add_argument(
        "--allow-local",
        action="store_true",
        help="the agent is a local target you own: loopback and private addresses may be dialled (metadata never)",
    )
    tls.set_defaults(run=_tls)
    corpus = sub.add_parser("corpus", help="score a verifier (module:function, served bytes to bool) on the 43 cards")
    corpus.add_argument("--verifier")
    corpus.set_defaults(run=_corpus)
    canon = sub.add_parser(
        "canonicaliser", help="run the 57 a2a-jcs-v01 vectors against a canonicaliser (module:function)"
    )
    canon.add_argument("--impl")
    canon.add_argument("--signing", help="module:function, card dict to signing bytes")
    canon.set_defaults(run=_canonicaliser)
    ssrf = sub.add_parser("ssrf", help="score a webhook judge (module:function, URL to refuse) on the 42 URLs")
    ssrf.add_argument("--judge", help="module:function; defaults to the reference judge on the recorded addresses")
    ssrf.set_defaults(run=_ssrf)
    args = parser.parse_args(argv)
    code: int = args.run(args)
    return code


if __name__ == "__main__":
    sys.exit(main())
