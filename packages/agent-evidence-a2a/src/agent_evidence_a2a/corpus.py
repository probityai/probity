"""The shipped card corpus and webhook SSRF corpus, and the scorers that judge a verifier against them."""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.resources import files
from typing import Any

from agent_evidence_a2a._data import data_json, data_jsonl
from agent_evidence_a2a.trust import TrustStore
from agent_evidence_a2a.verify import verify_served_card

CORPUS_CLOCK = datetime(2026, 9, 28, tzinfo=UTC)
"""The verification clock the expected verdicts were recorded at (it makes the expired key expired)."""


@dataclass(frozen=True, kw_only=True, slots=True)
class CardCase:
    """One served card with the verdict a correct verifier gives it."""

    id: str
    expected: str
    pending_on: str | None
    served: bytes


def load_cards() -> list[CardCase]:
    """Return the 43 cards: 11 ACCEPT, 28 REJECT and 4 PENDING probes."""
    root = files("agent_evidence_a2a").joinpath("data", "cards")
    return [
        CardCase(
            id=row["id"],
            expected=row["expected"],
            pending_on=row["pending_on"],
            served=root.joinpath(f"{row['id']}.json").read_bytes(),
        )
        for row in data_jsonl("cards.jsonl")
    ]


def load_trust_store() -> TrustStore:
    """Return the corpus trust store (kids kA, kB, kC and the expired kE)."""
    return TrustStore.from_mapping(data_json("truststore.json"))


def default_verifier() -> Callable[[bytes], bool]:
    """Return the package verifier bound to the corpus trust store and clock."""
    trust = load_trust_store()

    def accepts(served: bytes) -> bool:
        return verify_served_card(served, trust, now=CORPUS_CLOCK).accepted

    return accepts


@dataclass(frozen=True, kw_only=True, slots=True)
class CorpusReport:
    """A verifier's score on the card corpus; PENDING probes are listed, never scored."""

    detected: tuple[str, ...]
    missed: tuple[str, ...]
    false_rejects: tuple[str, ...]
    pending: tuple[str, ...]
    accepted_controls: int

    @property
    def ok(self) -> bool:
        """True when every REJECT card was rejected and no ACCEPT card was."""
        return not self.missed and not self.false_rejects


def score_card_verifier(accepts: Callable[[bytes], bool]) -> CorpusReport:
    """Score *accepts* (served bytes to accepted or not) on the 43-card corpus."""
    detected: list[str] = []
    missed: list[str] = []
    false_rejects: list[str] = []
    pending: list[str] = []
    controls = 0
    for case in load_cards():
        verdict = accepts(case.served)
        if case.expected == "PENDING":
            pending.append(case.id)
        elif case.expected == "REJECT":
            (missed if verdict else detected).append(case.id)
        elif verdict:
            controls += 1
        else:
            false_rejects.append(case.id)
    return CorpusReport(
        detected=tuple(detected),
        missed=tuple(missed),
        false_rejects=tuple(false_rejects),
        pending=tuple(pending),
        accepted_controls=controls,
    )


@dataclass(frozen=True, kw_only=True, slots=True)
class SsrfCase:
    """One webhook URL with the addresses an HTTP client resolved it to and the verdict that follows."""

    id: str
    url: str
    truth: str
    addrs: tuple[str, ...]
    scored: bool


def ground_truth(addrs: tuple[str, ...]) -> str:
    """UNSAFE when any address is not globally routable, SAFE when all are, UNFETCHABLE when there are none."""
    if not addrs:
        return "UNFETCHABLE"
    return "UNSAFE" if any(not ipaddress.ip_address(a).is_global for a in addrs) else "SAFE"


def load_ssrf() -> list[SsrfCase]:
    """Return the 42 URLs; ``scored`` is false for the one multicast URL left out of the score."""
    rows: list[dict[str, Any]] = data_jsonl("ssrf_urls.jsonl")
    return [
        SsrfCase(id=r["id"], url=r["url"], truth=r["truth"], addrs=tuple(r["addrs"] or ()), scored=r["scored"])
        for r in rows
    ]


@dataclass(frozen=True, kw_only=True, slots=True)
class SsrfReport:
    """A webhook judge's score: unsafe URLs it caught and missed, safe URLs it flagged."""

    caught: tuple[str, ...]
    missed: tuple[str, ...]
    false_flags: tuple[str, ...]
    unscored: tuple[str, ...]

    @property
    def ok(self) -> bool:
        """True when no UNSAFE URL was missed and no SAFE URL flagged."""
        return not self.missed and not self.false_flags


def score_ssrf_judge(flags: Callable[[str], bool]) -> SsrfReport:
    """Score *flags* (URL to "refuse this webhook") against the resolved ground truth."""
    caught: list[str] = []
    missed: list[str] = []
    false_flags: list[str] = []
    unscored: list[str] = []
    for case in load_ssrf():
        if not case.scored or case.truth == "UNFETCHABLE":
            unscored.append(case.id)
        elif case.truth == "UNSAFE":
            (caught if flags(case.url) else missed).append(case.id)
        elif flags(case.url):
            false_flags.append(case.id)
    return SsrfReport(
        caught=tuple(caught), missed=tuple(missed), false_flags=tuple(false_flags), unscored=tuple(unscored)
    )
