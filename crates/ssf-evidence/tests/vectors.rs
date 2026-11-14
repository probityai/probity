//! Builds the conformance vectors, checks the committed files match them byte
//! for byte, and runs every committed case through the receiver from the files
//! alone, as a third party would.
//!
//! Regenerate with `SSF_EVIDENCE_WRITE_VECTORS=1 cargo test -p ssf-evidence --test vectors`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use dsse::{Ed25519Signer, Ed25519Verifier, Envelope, Signature, Signer};
use serde_json::{Map, Value, json};
use ssf_evidence::evidence::{IN_TOTO_PAYLOAD_TYPE, STATEMENT_TYPE};
use ssf_evidence::transmitter::JtiSource;
use ssf_evidence::{
    Action, Capabilities, EVIDENCE_REF_CLAIM, EvidencePolicy, EvidenceRef, EvidenceTrust,
    MapResolver, Mode, Principal, RISK_LEVEL_CHANGE, ReceiverConfig, RiskLevel, SESSION_REVOKED,
    Signal, SigningKey, Stream, Subject, SubjectId, Transmitter, VerifyingKey, subject_descriptor,
    verify_set,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const ISSUER: &str = "https://transmitter.example.test/";
const AUDIENCE: &str = "https://receiver.example.test/ssf";
const NOW: u64 = 1_762_732_800;
const EVIDENCE_KEYID: &str = "test-evidence-ed25519";
const EVIDENCE_SEED: [u8; 32] = [0x11; 32];
const UNTRUSTED_SEED: [u8; 32] = [0x22; 32];
const TRANSMITTER_ED_SEED: [u8; 32] = [0x33; 32];
const TRANSMITTER_ED_KID: &str = "test-transmitter-ed25519";
const TEST_PREDICATE: &str = "https://example.test/predicate/v1/agent-decision";

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

struct Counter(u32);

impl JtiSource for Counter {
    fn next_jti(&mut self) -> String {
        self.0 += 1;
        format!("vector-{:04}", self.0)
    }
}

fn rsa_key() -> TestResult<SigningKey> {
    let der = std::fs::read(crate_dir().join("tests/keys/transmitter-rsa-2048.pk8"))?;
    Ok(SigningKey::rs256_from_pkcs8(&der)?.with_kid("test-transmitter-rs256"))
}

fn rsa_jwk() -> TestResult<Value> {
    let text =
        std::fs::read_to_string(crate_dir().join("tests/keys/transmitter-rsa-2048.jwk.json"))?;
    Ok(serde_json::from_str(&text)?)
}

fn ed_key() -> TestResult<SigningKey> {
    Ok(SigningKey::ed25519_from_seed(&TRANSMITTER_ED_SEED)?.with_kid(TRANSMITTER_ED_KID))
}

fn subject(user: &str) -> Subject {
    Subject {
        user: Some(SubjectId::IssSub {
            iss: "https://idp.example.test/".into(),
            sub: user.into(),
        }),
        agent: Some(SubjectId::Opaque {
            id: "agent-7".into(),
        }),
        tenant: Some(SubjectId::Opaque {
            id: "tenant-42".into(),
        }),
        session: Some(SubjectId::Opaque {
            id: "session-9".into(),
        }),
    }
}

fn statement(sub_id: &Value, statement_type: &str) -> TestResult<Vec<u8>> {
    Ok(serde_json::to_vec(&json!({
        "_type": statement_type,
        "subject": [subject_descriptor(sub_id)?],
        "predicateType": TEST_PREDICATE,
        "predicate": {"decision": "elevate-risk", "rule": "tool-call-outside-grant"},
    }))?)
}

fn envelope(payload: &[u8], payload_type: &str, seed: &[u8; 32]) -> TestResult<Vec<u8>> {
    let signer = Ed25519Signer::from_bytes(seed)?.with_key_id(EVIDENCE_KEYID);
    let signers: [&dyn Signer; 1] = [&signer];
    Ok(dsse::sign_with(payload_type, payload, &signers)?.to_json()?)
}

fn uri(id: &str) -> String {
    format!("https://evidence.example.test/e/{id}.dsse.json")
}

struct Case {
    id: &'static str,
    description: &'static str,
    token: String,
    served: BTreeMap<String, Vec<u8>>,
    accept: bool,
    code: Option<&'static str>,
    event_type: Option<&'static str>,
}

/// A valid evidence envelope for `user`, served at the case's URI.
fn good_evidence(id: &str, user: &str) -> TestResult<(EvidenceRef, BTreeMap<String, Vec<u8>>)> {
    let sub_id = subject(user).to_sub_id()?;
    let env = envelope(
        &statement(&sub_id, STATEMENT_TYPE)?,
        IN_TOTO_PAYLOAD_TYPE,
        &EVIDENCE_SEED,
    )?;
    let reference = EvidenceRef::for_envelope(&env, uri(id));
    Ok((reference, BTreeMap::from([(uri(id), env)])))
}

fn stream() -> Stream {
    Stream {
        stream_id: "stream-1".into(),
        audience: AUDIENCE.into(),
        events_delivered: vec![RISK_LEVEL_CHANGE.into(), SESSION_REVOKED.into()],
    }
}

/// Emits one signal through a live transmitter and returns the queued token.
fn emitted(key: SigningKey, caps: Capabilities, signal: &Signal) -> TestResult<String> {
    let mut tx = Transmitter::new(ISSUER, key, stream())
        .with_capabilities(caps)
        .with_jti_source(Box::new(Counter(0)));
    tx.set_mode(Mode::Live);
    tx.emit(signal, NOW)?;
    let entry = tx.outbox().entries().first().ok_or("nothing queued")?;
    Ok(entry.token.clone())
}

fn risk_signal(user: &str, evidence: EvidenceRef) -> Signal {
    Signal {
        subject: subject(user),
        action: Action::ChangeRisk {
            principal: Principal::Agent,
            current: RiskLevel::High,
            previous: Some(RiskLevel::Low),
            reason: Some("TOOL_CALL_OUTSIDE_GRANT".into()),
        },
        evidence,
        txn: Some("txn-1".into()),
        event_timestamp: Some(NOW - 5),
    }
}

/// A risk-level-change claim set, for refusal cases built by hand.
fn claims(evidence: Option<&EvidenceRef>) -> TestResult<Map<String, Value>> {
    let mut event = json!({
        "principal": "AGENT", "current_level": "HIGH", "previous_level": "LOW",
        "initiating_entity": "policy", "event_timestamp": NOW - 5,
    });
    if let (Some(r), Some(obj)) = (evidence, event.as_object_mut()) {
        obj.insert(EVIDENCE_REF_CLAIM.into(), r.to_value());
    }
    let value = json!({
        "iss": ISSUER, "aud": AUDIENCE, "iat": NOW, "jti": "vector-hand",
        "txn": "txn-1", "sub_id": subject("user-123").to_sub_id()?,
        "events": {RISK_LEVEL_CHANGE: event},
    });
    match value {
        Value::Object(map) => Ok(map),
        _ => Err("claims are not an object".into()),
    }
}

fn sign(claims: &Map<String, Value>) -> TestResult<String> {
    Ok(rsa_key()?.sign_compact(&serde_json::to_vec(claims)?)?)
}

fn sign_with_header(
    header: &Value,
    claims: &Map<String, Value>,
    key: &SigningKey,
) -> TestResult<String> {
    Ok(key.sign_raw(&serde_json::to_vec(header)?, &serde_json::to_vec(claims)?)?)
}

fn rs_header() -> Value {
    json!({"alg": "RS256", "typ": "secevent+jwt", "kid": "test-transmitter-rs256"})
}

fn refuse(
    id: &'static str,
    description: &'static str,
    token: String,
    served: BTreeMap<String, Vec<u8>>,
    code: &'static str,
) -> Case {
    Case {
        id,
        description,
        token,
        served,
        accept: false,
        code: Some(code),
        event_type: None,
    }
}

#[allow(clippy::too_many_lines)]
fn cases() -> TestResult<Vec<Case>> {
    let mut out = Vec::new();

    let (r, served) = good_evidence("accept-rlc-rs256", "user-123")?;
    out.push(Case {
        id: "accept-risk-level-change-rs256",
        description: "A risk-level-change about a user, agent, tenant and session, signed RS256, whose evidence resolves, hashes to its digest, verifies and names the same subject.",
        token: emitted(rsa_key()?, Capabilities::default(), &risk_signal("user-123", r))?,
        served, accept: true, code: None, event_type: Some(RISK_LEVEL_CHANGE),
    });

    let (r, served) = good_evidence("accept-revoked-rs256", "user-123")?;
    let revoke = Signal {
        action: Action::RevokeSession {
            reason_admin: "Agent called a tool outside its grant".into(),
        },
        ..risk_signal("user-123", r)
    };
    out.push(Case {
        id: "accept-session-revoked-rs256",
        description: "A session-revoked from a transmitter the receiver granted the session_revoke capability.",
        token: emitted(rsa_key()?, Capabilities { session_revoke: true }, &revoke)?,
        served: served.clone(), accept: true, code: None, event_type: Some(SESSION_REVOKED),
    });
    out.push(Case {
        id: "accept-revocation-downgraded-rs256",
        description: "The same revocation from a transmitter without the capability goes out as a HIGH risk-level-change.",
        token: emitted(rsa_key()?, Capabilities::default(), &revoke)?,
        served, accept: true, code: None, event_type: Some(RISK_LEVEL_CHANGE),
    });

    let (r, served) = good_evidence("accept-rlc-ed25519", "user-123")?;
    out.push(Case {
        id: "accept-risk-level-change-ed25519",
        description: "A risk-level-change signed with Ed25519 (RFC 9864).",
        token: emitted(
            ed_key()?,
            Capabilities::default(),
            &risk_signal("user-123", r),
        )?,
        served,
        accept: true,
        code: None,
        event_type: Some(RISK_LEVEL_CHANGE),
    });

    let mut tx =
        Transmitter::new(ISSUER, rsa_key()?, stream()).with_jti_source(Box::new(Counter(0)));
    out.push(Case {
        id: "accept-stream-verification",
        description: "An SSF stream verification event, which carries no evidence and needs none.",
        token: tx.verification_token("c3RhdGU", NOW)?,
        served: BTreeMap::new(),
        accept: true,
        code: None,
        event_type: Some(ssf_evidence::VERIFICATION),
    });

    let (r, _) = good_evidence("unresolved", "user-123")?;
    out.push(refuse(
        "refuse-evidence-unresolved",
        "The digest names an envelope nobody serves at the URI.",
        sign(&claims(Some(&r))?)?,
        BTreeMap::new(),
        "evidence.unresolved",
    ));

    let (r, mut served) = good_evidence("digest-mismatch", "user-123")?;
    let tampered = good_evidence("digest-mismatch", "user-999")?.1;
    served.extend(tampered);
    out.push(refuse(
        "refuse-evidence-digest-mismatch",
        "The URI serves an envelope other than the one the token's digest commits to.",
        sign(&claims(Some(&r))?)?,
        served,
        "evidence.digest_mismatch",
    ));

    let sub_id = subject("user-123").to_sub_id()?;
    let good = envelope(
        &statement(&sub_id, STATEMENT_TYPE)?,
        IN_TOTO_PAYLOAD_TYPE,
        &EVIDENCE_SEED,
    )?;
    let mut env = Envelope::from_json(&good)?;
    let mut altered: Value = serde_json::from_slice(&STANDARD.decode(&env.payload)?)?;
    if let Some(p) = altered.get_mut("predicate") {
        *p = json!({"decision": "no-action"});
    }
    env.payload = STANDARD.encode(serde_json::to_vec(&altered)?);
    let bytes = env.to_json()?;
    let r = EvidenceRef::for_envelope(&bytes, uri("tampered"));
    out.push(refuse(
        "refuse-evidence-tampered-envelope",
        "The token commits to an envelope whose payload was changed after it was signed.",
        sign(&claims(Some(&r))?)?,
        BTreeMap::from([(uri("tampered"), bytes)]),
        "evidence.signature",
    ));

    let (r, served) = good_evidence("wrong-subject", "user-999")?;
    out.push(refuse("refuse-evidence-wrong-subject",
        "The envelope verifies but its statement is about a different user than the token's sub_id.",
        sign(&claims(Some(&r))?)?, served, "evidence.subject_mismatch"));

    out.push(refuse(
        "refuse-evidence-absent",
        "The event carries no evidence reference.",
        sign(&claims(None)?)?,
        BTreeMap::new(),
        "evidence.absent",
    ));

    let bytes = envelope(
        &statement(&sub_id, STATEMENT_TYPE)?,
        IN_TOTO_PAYLOAD_TYPE,
        &UNTRUSTED_SEED,
    )?;
    let r = EvidenceRef::for_envelope(&bytes, uri("untrusted"));
    out.push(refuse(
        "refuse-evidence-untrusted-key",
        "The envelope is signed by a key the receiver does not trust.",
        sign(&claims(Some(&r))?)?,
        BTreeMap::from([(uri("untrusted"), bytes)]),
        "evidence.signature",
    ));

    let bytes = envelope(
        &statement(&sub_id, STATEMENT_TYPE)?,
        "application/json",
        &EVIDENCE_SEED,
    )?;
    let r = EvidenceRef::for_envelope(&bytes, uri("payload-type"));
    out.push(refuse(
        "refuse-evidence-payload-type",
        "The envelope's payloadType is not the in-toto type the claim names.",
        sign(&claims(Some(&r))?)?,
        BTreeMap::from([(uri("payload-type"), bytes)]),
        "evidence.payload_type",
    ));

    let (mut r, served) = good_evidence("claim-malformed", "user-123")?;
    r.sha256 = r.sha256.to_ascii_uppercase();
    out.push(refuse(
        "refuse-evidence-claim-malformed",
        "The claim's digest is not lowercase hex.",
        sign(&claims(Some(&r))?)?,
        served,
        "evidence.claim_malformed",
    ));

    let bytes = envelope(
        &statement(&sub_id, "https://in-toto.io/Statement/v0.1")?,
        IN_TOTO_PAYLOAD_TYPE,
        &EVIDENCE_SEED,
    )?;
    let r = EvidenceRef::for_envelope(&bytes, uri("not-statement"));
    out.push(refuse(
        "refuse-evidence-not-statement-v1",
        "The verified payload is not an in-toto Statement v1.",
        sign(&claims(Some(&r))?)?,
        BTreeMap::from([(uri("not-statement"), bytes)]),
        "evidence.statement",
    ));

    let (r, served) = good_evidence("set-signature", "user-123")?;
    let token = sign(&claims(Some(&r))?)?;
    let mut changed = claims(Some(&r))?;
    changed.insert("txn".into(), json!("txn-2"));
    let parts: Vec<&str> = token.split('.').collect();
    let forged = format!(
        "{}.{}.{}",
        parts.first().ok_or("header")?,
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&changed)?),
        parts.get(2).ok_or("signature")?
    );
    out.push(refuse(
        "refuse-set-signature",
        "A claim was changed after the token was signed.",
        forged,
        served.clone(),
        "set.signature",
    ));

    let base = claims(Some(&r))?;
    let key = rsa_key()?;
    out.push(refuse(
        "refuse-set-typ",
        "The typ header is JWT, not secevent+jwt.",
        sign_with_header(
            &json!({"alg": "RS256", "typ": "JWT", "kid": "test-transmitter-rs256"}),
            &base,
            &key,
        )?,
        served.clone(),
        "set.typ",
    ));
    let none = format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(
            &json!({"alg": "none", "typ": "secevent+jwt"})
        )?),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&base)?)
    );
    out.push(refuse(
        "refuse-set-alg-none",
        "An unsigned token (alg none).",
        none,
        served.clone(),
        "set.alg",
    ));
    out.push(refuse(
        "refuse-set-alg-key-mismatch",
        "The header asks for Ed25519 under the kid of the RSA key.",
        sign_with_header(
            &json!({"alg": "Ed25519", "typ": "secevent+jwt", "kid": "test-transmitter-rs256"}),
            &base,
            &ed_key()?,
        )?,
        served.clone(),
        "set.alg",
    ));
    out.push(refuse(
        "refuse-set-unknown-kid",
        "The kid names no trusted key.",
        sign_with_header(
            &json!({"alg": "RS256", "typ": "secevent+jwt", "kid": "rotated-away"}),
            &base,
            &key,
        )?,
        served.clone(),
        "set.unknown_key",
    ));
    out.push(refuse("refuse-set-crit", "The header marks an extension critical.",
        sign_with_header(&json!({"alg": "RS256", "typ": "secevent+jwt", "kid": "test-transmitter-rs256", "crit": ["b64"], "b64": true}), &base, &key)?,
        served.clone(), "set.crit"));

    let with = |name: &str, value: Value| -> TestResult<String> {
        let mut c = base.clone();
        c.insert(name.into(), value);
        sign(&c)
    };
    out.push(refuse(
        "refuse-set-sub-present",
        "The token carries sub, which SSF forbids.",
        with("sub", json!("user-123"))?,
        served.clone(),
        "set.sub_present",
    ));
    out.push(refuse(
        "refuse-set-exp-present",
        "The token carries exp, which SSF forbids.",
        with("exp", json!(NOW + 300))?,
        served.clone(),
        "set.exp_present",
    ));
    out.push(refuse(
        "refuse-set-wrong-issuer",
        "The issuer is not the stream's transmitter.",
        with("iss", json!("https://other.example.test/"))?,
        served.clone(),
        "set.iss",
    ));
    out.push(refuse(
        "refuse-set-wrong-audience",
        "The audience does not name this receiver.",
        with("aud", json!(["https://other-receiver.example.test/"]))?,
        served.clone(),
        "set.aud",
    ));
    let mut events = base.get("events").cloned().ok_or("events")?;
    if let Some(obj) = events.as_object_mut() {
        obj.insert(
            SESSION_REVOKED.into(),
            json!({"initiating_entity": "policy"}),
        );
    }
    out.push(refuse(
        "refuse-set-two-events",
        "The token carries two events.",
        with("events", events)?,
        served.clone(),
        "set.events",
    ));
    let mut events = base.get("events").cloned().ok_or("events")?;
    if let Some(e) = events
        .get_mut(RISK_LEVEL_CHANGE)
        .and_then(Value::as_object_mut)
    {
        e.insert("current_level".into(), json!("SEVERE"));
    }
    out.push(refuse(
        "refuse-set-risk-level-invalid",
        "current_level is not LOW, MEDIUM or HIGH.",
        with("events", events)?,
        served.clone(),
        "set.event_payload",
    ));

    let body = serde_json::to_string(&base)?;
    let duplicated = body.replacen('{', "{\"iss\":\"https://other.example.test/\",", 1);
    out.push(refuse("refuse-set-duplicate-member",
        "The payload repeats iss; a reader keeping the first value and one keeping the last would disagree.",
        key.sign_raw(&serde_json::to_vec(&rs_header())?, duplicated.as_bytes())?,
        served, "set.malformed"));

    Ok(out)
}

fn keys_json() -> TestResult<Value> {
    let ed = ed_key()?
        .ed25519_verifying_key()
        .ok_or("ed25519 key")?
        .to_jwk();
    Ok(json!({
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "transmitter_jwks": {"keys": [rsa_jwk()?, ed]},
        "evidence_keys": [{"keyid": EVIDENCE_KEYID, "ed25519_public_hex": hex(&ed25519_public(&EVIDENCE_SEED)?)}],
        "evidence_threshold": 1,
        "evidence_policy": "required",
        "claim": EVIDENCE_REF_CLAIM,
    }))
}

fn ed25519_public(seed: &[u8; 32]) -> TestResult<Vec<u8>> {
    let key = SigningKey::ed25519_from_seed(seed)?
        .ed25519_verifying_key()
        .ok_or("ed25519")?;
    let x = key
        .to_jwk()
        .get("x")
        .and_then(Value::as_str)
        .ok_or("x")?
        .to_string();
    Ok(URL_SAFE_NO_PAD.decode(x)?)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn case_json(case: &Case) -> Value {
    let served: Map<String, Value> = case
        .served
        .iter()
        .map(|(k, v)| (k.clone(), json!(STANDARD.encode(v))))
        .collect();
    let mut expect = json!({"accept": case.accept});
    if let Some(obj) = expect.as_object_mut() {
        if let Some(code) = case.code {
            obj.insert("code".into(), json!(code));
        }
        if let Some(t) = case.event_type {
            obj.insert("event_type".into(), json!(t));
        }
    }
    json!({"id": case.id, "description": case.description, "token": case.token,
           "served": served, "expect": expect})
}

fn render(value: &Value) -> TestResult<String> {
    Ok(serde_json::to_string_pretty(value)? + "\n")
}

#[test]
fn committed_vectors_match_the_generator() -> TestResult {
    let dir = crate_dir().join("vectors");
    let mut expected: BTreeMap<PathBuf, String> = BTreeMap::new();
    expected.insert(dir.join("keys.json"), render(&keys_json()?)?);
    for case in cases()? {
        expected.insert(
            dir.join("cases").join(format!("{}.json", case.id)),
            render(&case_json(&case))?,
        );
    }
    if std::env::var_os("SSF_EVIDENCE_WRITE_VECTORS").is_some() {
        std::fs::create_dir_all(dir.join("cases"))?;
        for (path, text) in &expected {
            std::fs::write(path, text)?;
        }
    }
    for (path, text) in &expected {
        let on_disk =
            std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        assert_eq!(
            &on_disk,
            text,
            "{} differs from the generator",
            path.display()
        );
    }
    let committed = std::fs::read_dir(dir.join("cases"))?.count();
    assert_eq!(
        committed,
        expected.len() - 1,
        "a committed case has no generator"
    );
    Ok(())
}

fn load(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn receiver_from_files(keys: &Value) -> TestResult<ReceiverConfig> {
    let mut transmitter_keys = Vec::new();
    for jwk in keys
        .pointer("/transmitter_jwks/keys")
        .and_then(Value::as_array)
        .ok_or("jwks")?
    {
        transmitter_keys.push(VerifyingKey::from_jwk(jwk)?);
    }
    let mut evidence_keys: Vec<Box<dyn dsse::Verifier + Send + Sync>> = Vec::new();
    for k in keys
        .get("evidence_keys")
        .and_then(Value::as_array)
        .ok_or("evidence_keys")?
    {
        let hex = k
            .get("ed25519_public_hex")
            .and_then(Value::as_str)
            .ok_or("hex")?;
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(hex.get(i..i + 2).unwrap_or("zz"), 16))
            .collect::<Result<_, _>>()?;
        let keyid = k.get("keyid").and_then(Value::as_str).ok_or("keyid")?;
        evidence_keys.push(Box::new(
            Ed25519Verifier::from_bytes(&bytes)?.with_key_id(keyid),
        ));
    }
    Ok(ReceiverConfig {
        issuer: keys
            .get("issuer")
            .and_then(Value::as_str)
            .ok_or("issuer")?
            .into(),
        audience: keys
            .get("audience")
            .and_then(Value::as_str)
            .ok_or("audience")?
            .into(),
        keys: transmitter_keys,
        evidence: EvidenceTrust {
            keys: evidence_keys,
            threshold: usize::try_from(
                keys.get("evidence_threshold")
                    .and_then(Value::as_u64)
                    .ok_or("threshold")?,
            )?,
            predicate_types: None,
        },
        evidence_policy: EvidencePolicy::Required,
    })
}

#[test]
fn every_committed_case_gets_its_expected_verdict() -> TestResult {
    let dir = crate_dir().join("vectors");
    let config = receiver_from_files(&load(&dir.join("keys.json"))?)?;
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir.join("cases"))?
        .map(|e| e.map(|e| e.path()))
        .collect::<Result<_, _>>()?;
    paths.sort();
    let (mut accepted, mut refused) = (0, 0);
    for path in paths {
        let case = load(&path)?;
        let mut resolver = MapResolver::new();
        for (uri, b64) in case
            .get("served")
            .and_then(Value::as_object)
            .ok_or("served")?
        {
            resolver.insert(uri.clone(), STANDARD.decode(b64.as_str().ok_or("b64")?)?);
        }
        let token = case.get("token").and_then(Value::as_str).ok_or("token")?;
        let expect = case.get("expect").ok_or("expect")?;
        let id = case.get("id").and_then(Value::as_str).ok_or("id")?;
        match (
            verify_set(token, &config, &resolver),
            expect.get("accept").and_then(Value::as_bool),
        ) {
            (Ok(v), Some(true)) => {
                assert_eq!(
                    Some(v.event_type.as_str()),
                    expect.get("event_type").and_then(Value::as_str),
                    "{id}"
                );
                accepted += 1;
            }
            (Err(r), Some(false)) => {
                assert_eq!(
                    Some(r.code.as_str()),
                    expect.get("code").and_then(Value::as_str),
                    "{id}: {r}"
                );
                refused += 1;
            }
            (got, _) => return Err(format!("{id}: unexpected verdict {got:?}").into()),
        }
    }
    assert_eq!((accepted, refused), (5, 22));
    Ok(())
}

#[test]
fn rs256_keys_below_2048_bits_are_refused() {
    let jwk = json!({"kty": "RSA", "n": URL_SAFE_NO_PAD.encode([0xffu8; 128]), "e": "AQAB"});
    assert!(VerifyingKey::from_jwk(&jwk).is_err());
}

#[test]
fn the_unsigned_signature_shape_is_rejected_by_dsse() -> TestResult {
    // An envelope whose only signature entry is empty never verifies.
    let env = Envelope {
        payload: STANDARD.encode(b"{}"),
        payload_type: IN_TOTO_PAYLOAD_TYPE.into(),
        signatures: vec![Signature {
            keyid: None,
            sig: String::new(),
        }],
    };
    let verifier = Ed25519Signer::from_bytes(&EVIDENCE_SEED)?.verifier();
    assert!(dsse::verify(&env, &[&verifier], 1).is_err());
    Ok(())
}
