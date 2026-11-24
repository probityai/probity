//! The receiving side: verify a token, then its evidence, then that it was not
//! accepted before.

use std::collections::HashMap;
use std::sync::Mutex;

use serde_json::{Map, Value};

use crate::error::{Code, Refusal};
use crate::evidence::{
    EVIDENCE_REF_CLAIM, EvidenceRef, EvidenceTrust, Resolver, VerifiedEvidence, sha256_hex,
    verify_evidence,
};
use crate::jws::{VerifyingKey, parse_object, verify_compact};

/// CAEP session revoked.
pub const SESSION_REVOKED: &str =
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
/// CAEP risk level change.
pub const RISK_LEVEL_CHANGE: &str =
    "https://schemas.openid.net/secevent/caep/event-type/risk-level-change";
/// SSF stream verification.
pub const VERIFICATION: &str = "https://schemas.openid.net/secevent/ssf/event-type/verification";
/// CAEP credential change (CAEP 1.0 section 3.3).
pub const CREDENTIAL_CHANGE: &str =
    "https://schemas.openid.net/secevent/caep/event-type/credential-change";

/// The `change_type` of a CAEP credential-change event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialChange {
    /// `create`: a credential was enrolled.
    Create,
    /// `revoke`: a credential was revoked.
    Revoke,
    /// `update`: a credential was changed, such as a password reset or a
    /// certificate renewal.
    Update,
    /// `delete`: a credential was deleted.
    Delete,
}

impl CredentialChange {
    /// The value CAEP 1.0 names, or `None` for any other string.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "create" => Some(Self::Create),
            "revoke" => Some(Self::Revoke),
            "update" => Some(Self::Update),
            "delete" => Some(Self::Delete),
            _ => None,
        }
    }

    /// The `change_type` string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Revoke => "revoke",
            Self::Update => "update",
            Self::Delete => "delete",
        }
    }
}

/// The revocation a verified token carries, decided once by the verifier from
/// the checked event type and payload so that no caller re-derives it from
/// strings.
///
/// A `risk-level-change` carries none, even at `HIGH`: a transmitter without
/// the `session_revoke` capability sends a revocation as `HIGH`, and a receiver
/// that wants to end work on it decides that itself. Stream verification
/// carries none.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Revocation {
    /// CAEP `session-revoked`: the session the token's `sub_id` names ends.
    Session,
    /// CAEP `credential-change` with `change_type` `revoke`, `delete` or
    /// `update`: authority derived from the prior credential ends. `update`
    /// counts because CAEP lists password resets and certificate renewals
    /// under it, which replace the prior credential; a receiver that ends a
    /// session on a harmless update costs a sign-in, one that keeps it after a
    /// compromise reset costs the account. `create` revokes nothing and gives
    /// no revocation.
    Credential {
        /// The `credential_type`, such as `password` or `fido2-roaming`.
        credential_type: String,
        /// The `change_type`.
        change: CredentialChange,
    },
}

/// What a [`JtiLedger`] held for an issuer's `jti` when asked to record it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JtiSeen {
    /// Nothing: the token is recorded now.
    New,
    /// The same token, byte for byte: a retransmission or a replay.
    Same,
    /// A different token under the same issuer and `jti`.
    Different,
}

/// Remembers every issuer and `jti` a receiver accepted, so each token is
/// acted on once.
///
/// [`verify_set`] calls [`JtiLedger::record`] last, after every other check
/// passed, so a token refused for any other reason is never recorded and a
/// later delivery of it is judged afresh. `record` must be atomic: of two
/// concurrent calls for one issuer and `jti`, exactly one sees
/// [`JtiSeen::New`]. A durable ledger commits the record in the same
/// transaction as the receiver's work item for the event, so a crash never
/// leaves a recorded `jti` whose event was not acted on (RFC 8935 section 2:
/// persist, then acknowledge). A ledger that forgets an entry reopens replay
/// for that token: keep entries at least as long as tokens can be
/// redelivered.
pub trait JtiLedger {
    /// Records `jti` from `issuer` for the token whose bytes hash to
    /// `token_sha256` (lowercase hex), and reports what was there before.
    /// An `Err` means the ledger could not answer; the token is refused.
    fn record(&self, issuer: &str, jti: &str, token_sha256: &str) -> Result<JtiSeen, String>;
}

/// A [`JtiLedger`] held in memory, for one process and for tests.
#[derive(Debug, Default)]
pub struct MemoryJtiLedger {
    seen: Mutex<HashMap<(String, String), String>>,
}

impl MemoryJtiLedger {
    /// An empty ledger.
    pub fn new() -> Self {
        Self::default()
    }
}

impl JtiLedger for MemoryJtiLedger {
    fn record(&self, issuer: &str, jti: &str, token_sha256: &str) -> Result<JtiSeen, String> {
        let mut seen = self
            .seen
            .lock()
            .map_err(|_| "the ledger lock is poisoned".to_string())?;
        let key = (issuer.to_string(), jti.to_string());
        Ok(match seen.get(&key) {
            Some(prior) if prior == token_sha256 => JtiSeen::Same,
            Some(_) => JtiSeen::Different,
            None => {
                seen.insert(key, token_sha256.to_string());
                JtiSeen::New
            }
        })
    }
}

/// Whether an event must carry an evidence reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidencePolicy {
    /// Every event except stream verification must carry one that verifies.
    Required,
    /// An event without one is accepted; one that is present must verify.
    Optional,
}

/// What a receiver trusts and expects.
#[derive(Debug)]
pub struct ReceiverConfig {
    /// The transmitter's issuer.
    pub issuer: String,
    /// This receiver's audience value.
    pub audience: String,
    /// The transmitter's keys, as published at its `jwks_uri`.
    pub keys: Vec<VerifyingKey>,
    /// The keys evidence envelopes must verify under.
    pub evidence: EvidenceTrust,
    /// Whether events must carry evidence.
    pub evidence_policy: EvidencePolicy,
}

/// A token that verified, with its evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSet {
    /// The token's `jti`; receivers deduplicate on it.
    pub jti: String,
    /// The event type URI.
    pub event_type: String,
    /// The event object.
    pub event: Map<String, Value>,
    /// The `sub_id` claim.
    pub sub_id: Value,
    /// Every claim of the token.
    pub claims: Map<String, Value>,
    /// The verified evidence, when the event carries a reference.
    pub evidence: Option<VerifiedEvidence>,
    /// The revocation the token carries, if any.
    pub revocation: Option<Revocation>,
}

fn refuse<T>(code: Code, detail: impl Into<String>) -> Result<T, Refusal> {
    Err(Refusal::new(code, detail))
}

/// Verifies a compact SET: signature, the SSF profile, the CAEP payload of
/// `risk-level-change`, `credential-change` and stream verification, the
/// evidence reference, and last that `ledger` has not accepted this issuer's
/// `jti` before.
pub fn verify_set(
    token: &str,
    config: &ReceiverConfig,
    resolver: &dyn Resolver,
    ledger: &dyn JtiLedger,
) -> Result<VerifiedSet, Refusal> {
    verify_delivered(token, None, config, resolver, ledger)
}

/// [`verify_set`] for a token delivered under a `jti` named outside it, as an
/// RFC 8936 poll response names each token by member name: the token's own
/// `jti` must be `expected_jti`, checked before the ledger records anything.
pub(crate) fn verify_delivered(
    token: &str,
    expected_jti: Option<&str>,
    config: &ReceiverConfig,
    resolver: &dyn Resolver,
    ledger: &dyn JtiLedger,
) -> Result<VerifiedSet, Refusal> {
    let verified = verify_compact(token, &config.keys)?;
    let claims = parse_object(&verified.payload, "payload")?;

    if claims.get("iss").and_then(Value::as_str) != Some(config.issuer.as_str()) {
        return refuse(Code::SetIss, format!("iss is {:?}", claims.get("iss")));
    }
    let aud_ok = match claims.get("aud") {
        Some(Value::String(a)) => *a == config.audience,
        Some(Value::Array(list)) => list
            .iter()
            .any(|a| a.as_str() == Some(config.audience.as_str())),
        _ => false,
    };
    if !aud_ok {
        return refuse(
            Code::SetAud,
            format!("aud does not name {}", config.audience),
        );
    }
    if claims.contains_key("sub") {
        return refuse(Code::SetSubPresent, "SSF tokens carry sub_id, never sub");
    }
    if claims.contains_key("exp") {
        return refuse(Code::SetExpPresent, "SSF tokens never carry exp");
    }
    if claims.get("iat").and_then(Value::as_u64).is_none() {
        return refuse(Code::SetIat, "iat is not a non-negative integer");
    }
    let jti = claims
        .get("jti")
        .and_then(Value::as_str)
        .filter(|j| !j.is_empty())
        .ok_or_else(|| Refusal::new(Code::SetJti, "jti is absent"))?
        .to_string();
    if let Some(expected) = expected_jti.filter(|e| *e != jti) {
        return refuse(
            Code::PollSetKey,
            format!("the token's jti {jti:?} is delivered under {expected:?}"),
        );
    }
    let events = claims
        .get("events")
        .and_then(Value::as_object)
        .ok_or_else(|| Refusal::new(Code::SetEvents, "events is not an object"))?;
    let mut iter = events.iter();
    let (Some((event_type, event)), None) = (iter.next(), iter.next()) else {
        return refuse(Code::SetEvents, "events must carry exactly one event");
    };
    let event = event
        .as_object()
        .ok_or_else(|| Refusal::new(Code::SetEvents, "the event is not an object"))?
        .clone();
    let sub_id = claims
        .get("sub_id")
        .filter(|s| s.get("format").and_then(Value::as_str).is_some())
        .ok_or_else(|| Refusal::new(Code::SetSubId, "sub_id is absent or has no format"))?
        .clone();
    check_event_payload(event_type, &event)?;

    let evidence = match event.get(EVIDENCE_REF_CLAIM) {
        Some(value) => {
            let reference = EvidenceRef::from_value(value)?;
            Some(verify_evidence(
                &reference,
                &sub_id,
                resolver,
                &config.evidence,
            )?)
        }
        None if event_type == VERIFICATION
            || config.evidence_policy == EvidencePolicy::Optional =>
        {
            None
        }
        None => {
            return refuse(
                Code::EvidenceAbsent,
                "the event carries no evidence reference",
            );
        }
    };

    Ok(VerifiedSet {
        revocation: None,
        jti,
        event_type: event_type.clone(),
        event,
        sub_id,
        claims,
        evidence,
    })
}

fn check_replay(
    ledger: &dyn JtiLedger,
    issuer: &str,
    jti: &str,
    token: &str,
) -> Result<(), Refusal> {
    match ledger.record(issuer, jti, &sha256_hex(token.as_bytes())) {
        Ok(JtiSeen::New) => Ok(()),
        Ok(JtiSeen::Same) => refuse(
            Code::SetJtiReplayed,
            format!("jti {jti:?} was accepted before"),
        ),
        Ok(JtiSeen::Different) => refuse(
            Code::SetJtiReused,
            format!("jti {jti:?} was accepted before for a different token"),
        ),
        Err(e) => refuse(Code::SetJtiLedger, format!("jti {jti:?} not recorded: {e}")),
    }
}

fn revocation_of(event_type: &str, event: &Map<String, Value>) -> Option<Revocation> {
    match event_type {
        SESSION_REVOKED => Some(Revocation::Session),
        CREDENTIAL_CHANGE => {
            let change = event
                .get("change_type")
                .and_then(Value::as_str)
                .and_then(CredentialChange::parse)?;
            let credential_type = event.get("credential_type").and_then(Value::as_str)?;
            (change != CredentialChange::Create).then(|| Revocation::Credential {
                credential_type: credential_type.to_string(),
                change,
            })
        }
        _ => None,
    }
}

/// The CAEP 1.0 section 3.3.1 claims: `credential_type` a non-empty string,
/// `change_type` one of the four values, and each optional claim a string.
fn check_credential_change(event: &Map<String, Value>) -> Result<(), Refusal> {
    if !event
        .get("credential_type")
        .and_then(Value::as_str)
        .is_some_and(|t| !t.is_empty())
    {
        return refuse(
            Code::SetEventPayload,
            "credential_type is not a non-empty string",
        );
    }
    if event
        .get("change_type")
        .and_then(Value::as_str)
        .and_then(CredentialChange::parse)
        .is_none()
    {
        return refuse(
            Code::SetEventPayload,
            "change_type is not create, revoke, update or delete",
        );
    }
    for name in [
        "friendly_name",
        "x509_issuer",
        "x509_serial",
        "fido2_aaguid",
    ] {
        if event.get(name).is_some_and(|v| !v.is_string()) {
            return refuse(Code::SetEventPayload, format!("{name} is not a string"));
        }
    }
    Ok(())
}

fn check_event_payload(event_type: &str, event: &Map<String, Value>) -> Result<(), Refusal> {
    let level = |name: &str| {
        event
            .get(name)
            .and_then(Value::as_str)
            .map(|v| ["LOW", "MEDIUM", "HIGH"].contains(&v))
    };
    match event_type {
        RISK_LEVEL_CHANGE => {
            if level("current_level") != Some(true) {
                return refuse(
                    Code::SetEventPayload,
                    "current_level is not LOW, MEDIUM or HIGH",
                );
            }
            if level("previous_level") == Some(false) {
                return refuse(
                    Code::SetEventPayload,
                    "previous_level is not LOW, MEDIUM or HIGH",
                );
            }
            if event.get("principal").and_then(Value::as_str).is_none() {
                return refuse(Code::SetEventPayload, "principal is absent");
            }
            Ok(())
        }
        CREDENTIAL_CHANGE => Ok(()),
        VERIFICATION if event.get("state").is_some_and(|s| !s.is_string()) => {
            refuse(Code::SetEventPayload, "state is not a string")
        }
        _ => Ok(()),
    }
}
