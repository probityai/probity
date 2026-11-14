//! The receiving side: verify a token, then its evidence.

use serde_json::{Map, Value};

use crate::error::{Code, Refusal};
use crate::evidence::{
    EVIDENCE_REF_CLAIM, EvidenceRef, EvidenceTrust, Resolver, VerifiedEvidence, verify_evidence,
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
}

fn refuse<T>(code: Code, detail: impl Into<String>) -> Result<T, Refusal> {
    Err(Refusal::new(code, detail))
}

/// Verifies a compact SET: signature, the SSF profile, the CAEP payload of the
/// two event types this crate emits, and the evidence reference.
pub fn verify_set(
    token: &str,
    config: &ReceiverConfig,
    resolver: &dyn Resolver,
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
        jti,
        event_type: event_type.clone(),
        event,
        sub_id,
        claims,
        evidence,
    })
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
        VERIFICATION if event.get("state").is_some_and(|s| !s.is_string()) => {
            refuse(Code::SetEventPayload, "state is not a string")
        }
        _ => Ok(()),
    }
}
