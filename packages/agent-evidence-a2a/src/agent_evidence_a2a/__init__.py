"""Verify A2A agent card signatures over the served bytes, probe transport posture, and score verifiers."""

from agent_evidence_a2a.canonical import CardCanonicalizationError, served_signing_bytes
from agent_evidence_a2a.corpus import (
    CardCase,
    CorpusReport,
    SsrfCase,
    SsrfReport,
    load_cards,
    load_ssrf,
    score_card_verifier,
    score_ssrf_judge,
)
from agent_evidence_a2a.ssrf import judge_url, recorded_judge
from agent_evidence_a2a.transport import (
    HandshakeErrorKind,
    Outcome,
    Requirement,
    RequirementResult,
    TlsHandshakeResult,
    TransportReport,
    probe,
)
from agent_evidence_a2a.trust import TrustedKey, TrustStore
from agent_evidence_a2a.vectors import CanonicaliserReport, check_canonicaliser
from agent_evidence_a2a.verify import CardVerdict, Finding, verify_served_card

__version__ = "0.1.0"

__all__ = [
    "CanonicaliserReport",
    "CardCanonicalizationError",
    "CardCase",
    "CardVerdict",
    "CorpusReport",
    "Finding",
    "HandshakeErrorKind",
    "Outcome",
    "Requirement",
    "RequirementResult",
    "SsrfCase",
    "SsrfReport",
    "TlsHandshakeResult",
    "TransportReport",
    "TrustStore",
    "TrustedKey",
    "check_canonicaliser",
    "judge_url",
    "load_cards",
    "load_ssrf",
    "probe",
    "recorded_judge",
    "score_card_verifier",
    "score_ssrf_judge",
    "served_signing_bytes",
    "verify_served_card",
]
