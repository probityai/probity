//! The evidence reference claim, and the check that it resolves and verifies.
//!
//! An event that carries the claim names, by SHA-256 digest and retrieval URI,
//! a DSSE envelope whose payload is an in-toto Statement. The statement names
//! the event's subject among its subjects, by the SHA-256 digest of the RFC 8785
//! canonical form of the token's `sub_id`. A receiver acts on the event only
//! when the bytes at the URI hash to the digest, the envelope verifies under a
//! key it trusts, and the statement names the same subject.

use std::collections::BTreeMap;

use ring::digest::{SHA256, digest};
use serde_json::{Map, Value, json};

use crate::error::{Code, Refusal};

/// The claim name. It is a collision-resistant name in the sense of RFC 7519
/// section 4.2, and it sits inside the event object of the token.
pub const EVIDENCE_REF_CLAIM: &str = "https://w3id.org/agent-evidence/secevent/v1/evidence-ref";

/// The only envelope payload type this profile accepts.
pub const IN_TOTO_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// The in-toto Statement type the envelope payload must carry.
pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";

/// The `name` a producer gives the statement subject that stands for the
/// token's `sub_id`. A receiver matches on the digest, not the name.
pub const SUBJECT_DESCRIPTOR_NAME: &str = "ssf:sub_id";

/// The largest envelope a receiver retrieves, in bytes.
pub const MAX_ENVELOPE_BYTES: usize = 1 << 20;

/// The value of the evidence reference claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRef {
    /// Lowercase hex SHA-256 of the exact envelope bytes served at `uri`.
    pub sha256: String,
    /// Where the envelope is retrieved.
    pub uri: String,
    /// The envelope's `payloadType`.
    pub payload_type: String,
}

impl EvidenceRef {
    /// The reference to `envelope_bytes`, served at `uri`.
    pub fn for_envelope(envelope_bytes: &[u8], uri: impl Into<String>) -> Self {
        Self {
            sha256: sha256_hex(envelope_bytes),
            uri: uri.into(),
            payload_type: IN_TOTO_PAYLOAD_TYPE.into(),
        }
    }

    /// The claim value as JSON.
    pub fn to_value(&self) -> Value {
        json!({
            "digest": {"sha256": self.sha256},
            "uri": self.uri,
            "payload_type": self.payload_type,
        })
    }

    /// Reads and checks a claim value. Members it does not know are ignored,
    /// as SSF requires of unknown fields.
    pub fn from_value(value: &Value) -> Result<Self, Refusal> {
        let bad = |detail: &str| Refusal::new(Code::EvidenceClaimMalformed, detail);
        let obj = value
            .as_object()
            .ok_or_else(|| bad("the claim is not an object"))?;
        let sha256 = obj
            .get("digest")
            .and_then(Value::as_object)
            .and_then(|d| d.get("sha256"))
            .and_then(Value::as_str)
            .ok_or_else(|| bad("digest.sha256 is absent"))?;
        if sha256.len() != 64
            || !sha256
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(bad("digest.sha256 is not 64 lowercase hex characters"));
        }
        let uri = obj
            .get("uri")
            .and_then(Value::as_str)
            .filter(|u| !u.is_empty())
            .ok_or_else(|| bad("uri is absent"))?;
        let payload_type = obj
            .get("payload_type")
            .and_then(Value::as_str)
            .ok_or_else(|| bad("payload_type is absent"))?;
        if payload_type != IN_TOTO_PAYLOAD_TYPE {
            return Err(bad("payload_type is not application/vnd.in-toto+json"));
        }
        Ok(Self {
            sha256: sha256.into(),
            uri: uri.into(),
            payload_type: payload_type.into(),
        })
    }
}

/// Retrieves the bytes behind an evidence URI.
pub trait Resolver {
    /// The bytes at `uri`, or a description of why there are none.
    fn fetch(&self, uri: &str) -> Result<Vec<u8>, String>;
}

/// A resolver over bytes held in memory, for tests, vectors and receivers
/// that are handed the envelope alongside the token.
#[derive(Debug, Clone, Default)]
pub struct MapResolver {
    entries: BTreeMap<String, Vec<u8>>,
}

impl MapResolver {
    /// An empty resolver.
    pub fn new() -> Self {
        Self::default()
    }

    /// Serves `bytes` at `uri`.
    pub fn insert(&mut self, uri: impl Into<String>, bytes: Vec<u8>) {
        self.entries.insert(uri.into(), bytes);
    }
}

impl Resolver for MapResolver {
    fn fetch(&self, uri: &str) -> Result<Vec<u8>, String> {
        self.entries
            .get(uri)
            .cloned()
            .ok_or_else(|| format!("nothing is served at {uri}"))
    }
}

/// The keys an envelope must verify under.
pub struct EvidenceTrust {
    /// Trusted DSSE verification keys.
    pub keys: Vec<Box<dyn dsse::Verifier + Send + Sync>>,
    /// How many distinct keys must verify.
    pub threshold: usize,
    /// When set, the predicate types a statement may carry.
    pub predicate_types: Option<Vec<String>>,
}

impl std::fmt::Debug for EvidenceTrust {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvidenceTrust")
            .field("keys", &self.keys.len())
            .field("threshold", &self.threshold)
            .field("predicate_types", &self.predicate_types)
            .finish()
    }
}

/// What a verified evidence reference established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEvidence {
    /// The envelope digest the token committed to.
    pub envelope_sha256: String,
    /// The verified in-toto Statement.
    pub statement: Map<String, Value>,
    /// The trusted keys that verified the envelope.
    pub accepted_keys: Vec<String>,
}

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The SHA-256 of the RFC 8785 canonical form of a `sub_id` value.
pub fn subject_digest(sub_id: &Value) -> Result<String, Refusal> {
    let bytes = serde_json::to_vec(sub_id)
        .map_err(|e| Refusal::new(Code::SetSubId, format!("sub_id: {e}")))?;
    let canonical = jcs_admit::admit(&bytes).map_err(|e| {
        Refusal::new(
            Code::SetSubId,
            format!("sub_id is not canonicalizable: {e}"),
        )
    })?;
    Ok(sha256_hex(&canonical))
}

/// The in-toto ResourceDescriptor a producer puts among the statement's
/// subjects so the statement names the token's subject.
pub fn subject_descriptor(sub_id: &Value) -> Result<Value, Refusal> {
    Ok(json!({
        "name": SUBJECT_DESCRIPTOR_NAME,
        "digest": {"sha256": subject_digest(sub_id)?},
    }))
}

/// Resolves and verifies an evidence reference for the subject `sub_id`.
pub fn verify_evidence(
    reference: &EvidenceRef,
    sub_id: &Value,
    resolver: &dyn Resolver,
    trust: &EvidenceTrust,
) -> Result<VerifiedEvidence, Refusal> {
    let bytes = resolver
        .fetch(&reference.uri)
        .map_err(|e| Refusal::new(Code::EvidenceUnresolved, e))?;
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(Refusal::new(
            Code::EvidenceUnresolved,
            format!("the envelope exceeds {MAX_ENVELOPE_BYTES} bytes"),
        ));
    }
    let actual = sha256_hex(&bytes);
    if actual != reference.sha256 {
        return Err(Refusal::new(
            Code::EvidenceDigestMismatch,
            format!(
                "the token commits to sha256 {} and the URI serves {actual}",
                reference.sha256
            ),
        ));
    }
    let envelope = dsse::Envelope::from_json(&bytes)
        .map_err(|e| Refusal::new(Code::EvidenceEnvelopeMalformed, e.to_string()))?;
    if envelope.payload_type != reference.payload_type {
        return Err(Refusal::new(
            Code::EvidencePayloadType,
            format!("the envelope's payloadType is {:?}", envelope.payload_type),
        ));
    }
    let keys: Vec<&dyn dsse::Verifier> = trust
        .keys
        .iter()
        .map(|k| k.as_ref() as &dyn dsse::Verifier)
        .collect();
    let verified = dsse::verify(&envelope, &keys, trust.threshold)
        .map_err(|e| Refusal::new(Code::EvidenceSignature, e.to_string()))?;
    let statement = crate::jws::parse_object(&verified.payload, "statement")
        .map_err(|r| Refusal::new(Code::EvidenceStatement, r.detail))?;
    if statement.get("_type").and_then(Value::as_str) != Some(STATEMENT_TYPE) {
        return Err(Refusal::new(
            Code::EvidenceStatement,
            "the payload is not an in-toto Statement v1",
        ));
    }
    let predicate_type = statement
        .get("predicateType")
        .and_then(Value::as_str)
        .ok_or_else(|| Refusal::new(Code::EvidenceStatement, "predicateType is absent"))?;
    if let Some(allowed) = &trust.predicate_types
        && !allowed.iter().any(|t| t == predicate_type)
    {
        return Err(Refusal::new(
            Code::EvidencePredicateType,
            format!("predicateType {predicate_type} is not accepted"),
        ));
    }
    let want = subject_digest(sub_id)?;
    let subjects = statement
        .get("subject")
        .and_then(Value::as_array)
        .ok_or_else(|| Refusal::new(Code::EvidenceStatement, "subject is absent"))?;
    let named = subjects.iter().any(|s| {
        s.get("digest")
            .and_then(|d| d.get("sha256"))
            .and_then(Value::as_str)
            == Some(want.as_str())
    });
    if !named {
        return Err(Refusal::new(
            Code::EvidenceSubjectMismatch,
            format!("no statement subject has the sub_id digest {want}"),
        ));
    }
    Ok(VerifiedEvidence {
        envelope_sha256: actual,
        statement,
        accepted_keys: verified.accepted_keys,
    })
}
