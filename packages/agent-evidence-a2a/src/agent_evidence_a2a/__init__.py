"""Verify A2A agent card signatures over the served bytes, probe transport posture, and score verifiers."""

from agent_evidence_a2a.canonical import (
    MAX_CARD_BYTES,
    REFERENCE_SIGNER_FORM,
    CardCanonicalizationError,
    SignedParts,
    non_jcs_forms,
    served_signing_bytes,
    signed_parts,
)
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
from agent_evidence_a2a.detached import (
    DEFAULT_ALGORITHMS,
    MAX_HEADER_BYTES,
    verify_detached,
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
from agent_evidence_a2a.trust import (
    KeyLookup,
    PinnedKey,
    TrustedKey,
    TrustStore,
    outside_window,
)
from agent_evidence_a2a.vectors import CanonicaliserReport, check_canonicaliser
from agent_evidence_a2a.verify import (
    CardVerdict,
    Finding,
    SignatureJudgement,
    SignedCard,
    UnreadableCard,
    judge_signature,
    read_signed_card,
    settle_signatures,
    verify_served_card,
)

__version__ = "0.1.0"

__all__ = [
    "DEFAULT_ALGORITHMS",
    "MAX_CARD_BYTES",
    "MAX_HEADER_BYTES",
    "REFERENCE_SIGNER_FORM",
    "CanonicaliserReport",
    "CardCanonicalizationError",
    "CardCase",
    "CardVerdict",
    "CorpusReport",
    "Finding",
    "HandshakeErrorKind",
    "KeyLookup",
    "Outcome",
    "PinnedKey",
    "Requirement",
    "RequirementResult",
    "SignatureJudgement",
    "SignedCard",
    "SignedParts",
    "SsrfCase",
    "SsrfReport",
    "TlsHandshakeResult",
    "TransportReport",
    "TrustStore",
    "TrustedKey",
    "UnreadableCard",
    "check_canonicaliser",
    "judge_signature",
    "judge_url",
    "load_cards",
    "load_ssrf",
    "non_jcs_forms",
    "outside_window",
    "probe",
    "read_signed_card",
    "recorded_judge",
    "score_card_verifier",
    "score_ssrf_judge",
    "served_signing_bytes",
    "settle_signatures",
    "signed_parts",
    "verify_detached",
    "verify_served_card",
]
