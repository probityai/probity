//! Typed refusals and errors.

use std::fmt;

/// A stable code for every reason a receiver refuses a Security Event Token.
///
/// The string form ([`Code::as_str`]) is what the conformance vectors expect,
/// so it never changes for an existing variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Code {
    /// The token is not three canonical base64url segments of JSON objects, or
    /// a JSON object repeats a member.
    SetMalformed,
    /// The `typ` header is not `secevent+jwt`.
    SetTyp,
    /// The header carries `crit`; this profile understands no extension.
    SetCrit,
    /// The `alg` header is absent, `none`, unsupported, or does not match the key.
    SetAlg,
    /// No trusted transmitter key matches the header.
    SetUnknownKey,
    /// The signature does not verify under the selected key.
    SetSignature,
    /// `iss` is absent or is not the configured issuer.
    SetIss,
    /// `aud` is absent or does not name the configured audience.
    SetAud,
    /// `sub` is present; SSF forbids it.
    SetSubPresent,
    /// `exp` is present; SSF forbids it.
    SetExpPresent,
    /// `iat` is absent or is not a non-negative integer.
    SetIat,
    /// `jti` is absent or empty.
    SetJti,
    /// `events` is absent, empty, or carries more than one event.
    SetEvents,
    /// `sub_id` is absent or is not a subject identifier object.
    SetSubId,
    /// The event payload does not conform to its event type.
    SetEventPayload,
    /// The event carries no evidence reference and the receiver requires one.
    EvidenceAbsent,
    /// The evidence reference claim is not well formed.
    EvidenceClaimMalformed,
    /// The evidence URI returned no bytes.
    EvidenceUnresolved,
    /// The bytes at the evidence URI do not hash to the digest in the token.
    EvidenceDigestMismatch,
    /// The bytes at the evidence URI are not a DSSE envelope.
    EvidenceEnvelopeMalformed,
    /// The envelope's `payloadType` differs from the one the claim names.
    EvidencePayloadType,
    /// The envelope does not verify under the trusted evidence keys.
    EvidenceSignature,
    /// The verified payload is not an in-toto Statement.
    EvidenceStatement,
    /// The statement's predicate type is not one the receiver accepts.
    EvidencePredicateType,
    /// The statement names no subject whose digest is the token's `sub_id`.
    EvidenceSubjectMismatch,
    /// This issuer's `jti` was accepted before, with the same token bytes: a
    /// retransmission or a replay. The receiver does not act on it again.
    SetJtiReplayed,
    /// This issuer's `jti` was accepted before for a different token.
    SetJtiReused,
    /// The replay ledger could not record the `jti`, so the token was not
    /// accepted. A later delivery of the same token can succeed.
    SetJtiLedger,
    /// A push request's `Content-Type` is not `application/secevent+jwt`.
    PushContentType,
    /// A push request does not carry the credential the receiver requires of
    /// its transmitter.
    PushAuthentication,
    /// A poll request is not the RFC 8936 JSON document.
    PollRequest,
    /// A poll response is not the RFC 8936 JSON document.
    PollResponse,
    /// A token in a poll response sits under a member name other than its own
    /// `jti`.
    PollSetKey,
    /// The poll request was not sent, or was not answered with HTTP 200.
    PollTransport,
}

impl Code {
    /// The stable string form of the code.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SetMalformed => "set.malformed",
            Self::SetTyp => "set.typ",
            Self::SetCrit => "set.crit",
            Self::SetAlg => "set.alg",
            Self::SetUnknownKey => "set.unknown_key",
            Self::SetSignature => "set.signature",
            Self::SetIss => "set.iss",
            Self::SetAud => "set.aud",
            Self::SetSubPresent => "set.sub_present",
            Self::SetExpPresent => "set.exp_present",
            Self::SetIat => "set.iat",
            Self::SetJti => "set.jti",
            Self::SetEvents => "set.events",
            Self::SetSubId => "set.sub_id",
            Self::SetEventPayload => "set.event_payload",
            Self::EvidenceAbsent => "evidence.absent",
            Self::EvidenceClaimMalformed => "evidence.claim_malformed",
            Self::EvidenceUnresolved => "evidence.unresolved",
            Self::EvidenceDigestMismatch => "evidence.digest_mismatch",
            Self::EvidenceEnvelopeMalformed => "evidence.envelope_malformed",
            Self::EvidencePayloadType => "evidence.payload_type",
            Self::EvidenceSignature => "evidence.signature",
            Self::EvidenceStatement => "evidence.statement",
            Self::EvidencePredicateType => "evidence.predicate_type",
            Self::EvidenceSubjectMismatch => "evidence.subject_mismatch",
            Self::SetJtiReplayed => "set.jti_replayed",
            Self::SetJtiReused => "set.jti_reused",
            Self::SetJtiLedger => "set.jti_ledger",
            Self::PushContentType => "push.content_type",
            Self::PushAuthentication => "push.authentication",
            Self::PollRequest => "poll.request_malformed",
            Self::PollResponse => "poll.response_malformed",
            Self::PollSetKey => "poll.set_key",
            Self::PollTransport => "poll.transport",
        }
    }

    /// The RFC 8935 Security Event Token Error Code a receiver reports when
    /// it refuses a token for this reason: the `err` of a push answer, or of
    /// an RFC 8936 `setErrs` entry. Every code maps to exactly one value.
    pub fn set_error_code(self) -> &'static str {
        match self {
            Self::SetAlg | Self::SetUnknownKey | Self::SetSignature => "invalid_key",
            Self::SetIss => "invalid_issuer",
            Self::SetAud => "invalid_audience",
            Self::PushAuthentication => "authentication_failed",
            _ => "invalid_request",
        }
    }

    /// Whether the refusal says nothing about the token itself: the receiver
    /// could not finish validating it (the evidence did not resolve, the
    /// replay ledger failed, the poll did not complete). A push receiver
    /// answers such a refusal with HTTP 503 and a poll receiver neither
    /// acknowledges nor reports the token, so the transmitter delivers it
    /// again (RFC 8935 section 2, "potentially recoverable errors").
    pub fn is_transient(self) -> bool {
        matches!(
            self,
            Self::EvidenceUnresolved | Self::SetJtiLedger | Self::PollTransport
        )
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a receiver refused a token: a stable code and a human-readable detail.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code}: {detail}")]
pub struct Refusal {
    /// The stable reason.
    pub code: Code,
    /// What was observed, for logs.
    pub detail: String,
}

impl Refusal {
    pub(crate) fn new(code: Code, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

/// Errors on the transmitting side: keys, configuration and delivery.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A key could not be constructed or is too weak.
    #[error("invalid key: {0}")]
    Key(String),
    /// Signing failed.
    #[error("signing failed: {0}")]
    Signing(String),
    /// A value could not be built into a token.
    #[error("invalid input: {0}")]
    Input(String),
    /// The transmitter's own evidence check refused the signal.
    #[error("evidence preflight refused the signal: {0}")]
    Preflight(Refusal),
    /// A delivery queue operation was refused.
    #[error("delivery: {0}")]
    Delivery(String),
}
