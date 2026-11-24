//! The receiving side: CAEP credential-change, the typed revocation outcome,
//! replay refusal, the RFC 8935 push answer and RFC 8936 polling.

use std::cell::RefCell;

use dsse::{Ed25519Signer, Signer};
use serde_json::{Map, Value, json};
use ssf_evidence::evidence::{IN_TOTO_PAYLOAD_TYPE, STATEMENT_TYPE};
use ssf_evidence::{
    CREDENTIAL_CHANGE, Code, CredentialChange, EVIDENCE_REF_CLAIM, EvidencePolicy, EvidenceRef,
    EvidenceTrust, JtiLedger, JtiSeen, MapResolver, MemoryJtiLedger, PollRequest, PollResponse,
    PollTransport, PushReceiver, PushResponse, RISK_LEVEL_CHANGE, ReceiverConfig, Refusal,
    Revocation, SESSION_REVOKED, SigningKey, Subject, SubjectId, VERIFICATION, poll_once,
    verify_set,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const ISSUER: &str = "https://transmitter.example.test/";
const AUDIENCE: &str = "https://receiver.example.test/ssf";
const SEED: [u8; 32] = [0x66; 32];
const EVIDENCE_SEED: [u8; 32] = [0x77; 32];
const URI: &str = "https://evidence.example.test/e/r.dsse.json";
const NOW: u64 = 1_762_732_800;

fn sub_id() -> TestResult<Value> {
    Ok(Subject {
        user: Some(SubjectId::Email {
            email: "user@example.test".into(),
        }),
        agent: Some(SubjectId::Opaque {
            id: "agent-1".into(),
        }),
        tenant: None,
        session: Some(SubjectId::Opaque {
            id: "session-1".into(),
        }),
    }
    .to_sub_id()?)
}

/// An evidence reference for the test subject, and a resolver that serves it.
fn evidence() -> TestResult<(EvidenceRef, MapResolver)> {
    let statement = serde_json::to_vec(&json!({
        "_type": STATEMENT_TYPE,
        "subject": [ssf_evidence::subject_descriptor(&sub_id()?)?],
        "predicateType": "https://example.test/predicate/v1/agent-decision",
        "predicate": {},
    }))?;
    let signer = Ed25519Signer::from_bytes(&EVIDENCE_SEED)?.with_key_id("ev");
    let signers: [&dyn Signer; 1] = [&signer];
    let bytes = dsse::sign_with(IN_TOTO_PAYLOAD_TYPE, &statement, &signers)?.to_json()?;
    let mut resolver = MapResolver::new();
    resolver.insert(URI, bytes.clone());
    Ok((EvidenceRef::for_envelope(&bytes, URI), resolver))
}

fn config() -> TestResult<ReceiverConfig> {
    let key = SigningKey::ed25519_from_seed(&SEED)?.with_kid("tx");
    let verifier = Ed25519Signer::from_bytes(&EVIDENCE_SEED)?
        .with_key_id("ev")
        .verifier();
    Ok(ReceiverConfig {
        issuer: ISSUER.into(),
        audience: AUDIENCE.into(),
        keys: vec![key.ed25519_verifying_key().ok_or("key")?],
        evidence: EvidenceTrust {
            keys: vec![Box::new(verifier)],
            threshold: 1,
            predicate_types: None,
        },
        evidence_policy: EvidencePolicy::Required,
    })
}

/// A signed token carrying one event of `event_type` with `event`'s members
/// and an evidence reference.
fn token(jti: &str, event_type: &str, event: Value, r: &EvidenceRef) -> TestResult<String> {
    let mut event = match event {
        Value::Object(map) => map,
        _ => return Err("event is not an object".into()),
    };
    event.insert(EVIDENCE_REF_CLAIM.into(), r.to_value());
    let claims = json!({
        "iss": ISSUER, "aud": AUDIENCE, "iat": NOW, "jti": jti,
        "sub_id": sub_id()?, "events": {event_type: Value::Object(event)},
    });
    let key = SigningKey::ed25519_from_seed(&SEED)?.with_kid("tx");
    Ok(key.sign_compact(&serde_json::to_vec(&claims)?)?)
}

fn credential_change(jti: &str, change_type: &str, r: &EvidenceRef) -> TestResult<String> {
    token(
        jti,
        CREDENTIAL_CHANGE,
        json!({"credential_type": "password", "change_type": change_type,
               "initiating_entity": "admin"}),
        r,
    )
}

fn risk(jti: &str, level: &str, r: &EvidenceRef) -> TestResult<String> {
    token(
        jti,
        RISK_LEVEL_CHANGE,
        json!({"principal": "AGENT", "current_level": level}),
        r,
    )
}

fn code_of<T: std::fmt::Debug>(result: Result<T, Refusal>) -> TestResult<Code> {
    match result {
        Err(r) => Ok(r.code),
        Ok(v) => Err(format!("accepted: {v:?}").into()),
    }
}

// --- CAEP credential-change ---------------------------------------------------

#[test]
fn credential_change_with_unknown_change_type_is_refused() -> TestResult {
    let (r, resolver) = evidence()?;
    let t = credential_change("cc-1", "rotate", &r)?;
    let got = verify_set(&t, &config()?, &resolver, &MemoryJtiLedger::new());
    assert_eq!(code_of(got)?, Code::SetEventPayload);
    Ok(())
}

#[test]
fn credential_change_without_a_credential_type_string_is_refused() -> TestResult {
    let (r, resolver) = evidence()?;
    for event in [
        json!({"change_type": "revoke"}),
        json!({"credential_type": "", "change_type": "revoke"}),
        json!({"credential_type": 7, "change_type": "revoke"}),
        json!({"credential_type": "x509", "change_type": "revoke", "x509_serial": 12}),
    ] {
        let t = token("cc-2", CREDENTIAL_CHANGE, event.clone(), &r)?;
        let got = verify_set(&t, &config()?, &resolver, &MemoryJtiLedger::new());
        assert_eq!(code_of(got)?, Code::SetEventPayload, "{event}");
    }
    Ok(())
}

#[test]
fn credential_change_revoke_delete_and_update_carry_a_credential_revocation() -> TestResult {
    let (r, resolver) = evidence()?;
    for (change_type, change) in [
        ("revoke", CredentialChange::Revoke),
        ("delete", CredentialChange::Delete),
        ("update", CredentialChange::Update),
    ] {
        let t = credential_change(&format!("cc-{change_type}"), change_type, &r)?;
        let set = verify_set(&t, &config()?, &resolver, &MemoryJtiLedger::new())?;
        assert_eq!(set.event_type, CREDENTIAL_CHANGE);
        assert_eq!(
            set.revocation,
            Some(Revocation::Credential {
                credential_type: "password".into(),
                change,
            })
        );
    }
    Ok(())
}

#[test]
fn credential_change_create_carries_no_revocation() -> TestResult {
    let (r, resolver) = evidence()?;
    let t = credential_change("cc-create", "create", &r)?;
    let set = verify_set(&t, &config()?, &resolver, &MemoryJtiLedger::new())?;
    assert_eq!(set.revocation, None);
    Ok(())
}

// --- typed revocation outcome ---------------------------------------------------

#[test]
fn session_revoked_carries_a_session_revocation() -> TestResult {
    let (r, resolver) = evidence()?;
    let t = token(
        "sr-1",
        SESSION_REVOKED,
        json!({"initiating_entity": "policy"}),
        &r,
    )?;
    let set = verify_set(&t, &config()?, &resolver, &MemoryJtiLedger::new())?;
    assert_eq!(set.revocation, Some(Revocation::Session));
    Ok(())
}

#[test]
fn a_high_risk_level_change_carries_no_revocation() -> TestResult {
    let (r, resolver) = evidence()?;
    let t = risk("rlc-1", "HIGH", &r)?;
    let set = verify_set(&t, &config()?, &resolver, &MemoryJtiLedger::new())?;
    assert_eq!(set.revocation, None);
    Ok(())
}

// --- replay ---------------------------------------------------------------------

#[test]
fn a_replayed_jti_is_refused() -> TestResult {
    let (r, resolver) = evidence()?;
    let ledger = MemoryJtiLedger::new();
    let t = risk("rlc-low", "LOW", &r)?;
    verify_set(&t, &config()?, &resolver, &ledger)?;
    let again = verify_set(&t, &config()?, &resolver, &ledger);
    assert_eq!(code_of(again)?, Code::SetJtiReplayed);
    Ok(())
}

#[test]
fn a_reused_jti_on_a_different_token_is_refused() -> TestResult {
    let (r, resolver) = evidence()?;
    let ledger = MemoryJtiLedger::new();
    verify_set(&risk("rlc-x", "HIGH", &r)?, &config()?, &resolver, &ledger)?;
    // An old LOW under the same jti must not undo the HIGH.
    let got = verify_set(&risk("rlc-x", "LOW", &r)?, &config()?, &resolver, &ledger);
    assert_eq!(code_of(got)?, Code::SetJtiReused);
    Ok(())
}

#[test]
fn a_token_refused_for_another_reason_is_not_recorded() -> TestResult {
    let (r, resolver) = evidence()?;
    let ledger = MemoryJtiLedger::new();
    let t = risk("rlc-late", "HIGH", &r)?;
    let first = verify_set(&t, &config()?, &MapResolver::new(), &ledger);
    assert_eq!(code_of(first)?, Code::EvidenceUnresolved);
    // Once the evidence is served, the same token is judged afresh.
    verify_set(&t, &config()?, &resolver, &ledger)?;
    Ok(())
}

struct BrokenLedger;

impl JtiLedger for BrokenLedger {
    fn record(&self, _: &str, _: &str, _: &str) -> Result<JtiSeen, String> {
        Err("disk full".into())
    }
}

#[test]
fn a_ledger_that_cannot_record_refuses_the_token() -> TestResult {
    let (r, resolver) = evidence()?;
    let got = verify_set(
        &risk("rlc-b", "HIGH", &r)?,
        &config()?,
        &resolver,
        &BrokenLedger,
    );
    assert_eq!(code_of(got)?, Code::SetJtiLedger);
    Ok(())
}

// --- RFC 8935 push ----------------------------------------------------------------

fn push_body(response: &PushResponse) -> TestResult<Value> {
    Ok(serde_json::from_str(&response.body())?)
}

#[test]
fn push_accepts_a_verified_token_with_an_empty_202() -> TestResult {
    let (r, resolver) = evidence()?;
    let config = config()?;
    let ledger = MemoryJtiLedger::new();
    let receiver = PushReceiver {
        config: &config,
        resolver: &resolver,
        ledger: &ledger,
        authorization: None,
    };
    let t = credential_change("p-1", "revoke", &r)?;
    let response = receiver.receive(Some("application/secevent+jwt"), None, t.as_bytes());
    assert_eq!(response.status(), 202);
    assert_eq!(response.body(), "");
    let PushResponse::Accepted(set) = response else {
        return Err(format!("not accepted: {response:?}").into());
    };
    assert!(matches!(
        set.revocation,
        Some(Revocation::Credential { .. })
    ));
    Ok(())
}

#[test]
fn push_with_a_wrong_content_type_is_invalid_request() -> TestResult {
    let (r, resolver) = evidence()?;
    let config = config()?;
    let ledger = MemoryJtiLedger::new();
    let receiver = PushReceiver {
        config: &config,
        resolver: &resolver,
        ledger: &ledger,
        authorization: None,
    };
    let t = risk("p-ct", "HIGH", &r)?;
    for content_type in [
        None,
        Some("application/jwt"),
        Some("application/json"),
        Some("application/secevent+jwtx"),
    ] {
        let response = receiver.receive(content_type, None, t.as_bytes());
        assert_eq!(response.status(), 400, "{content_type:?}");
        assert_eq!(push_body(&response)?["err"], "invalid_request");
        assert!(matches!(
            response,
            PushResponse::Refused(Refusal {
                code: Code::PushContentType,
                ..
            })
        ));
        assert!(
            response
                .headers()
                .contains(&("Content-Type", "application/json"))
        );
        assert!(
            response
                .headers()
                .iter()
                .any(|(name, _)| *name == "Content-Language")
        );
    }
    // A media type compares without regard to case and parameters.
    let response = receiver.receive(
        Some("Application/SecEvent+JWT; charset=utf-8"),
        None,
        t.as_bytes(),
    );
    assert_eq!(response.status(), 202);
    Ok(())
}

#[test]
fn push_retransmission_answers_202_and_is_not_acted_on() -> TestResult {
    let (r, resolver) = evidence()?;
    let config = config()?;
    let ledger = MemoryJtiLedger::new();
    let receiver = PushReceiver {
        config: &config,
        resolver: &resolver,
        ledger: &ledger,
        authorization: None,
    };
    let t = risk("p-again", "HIGH", &r)?;
    let ct = Some(ssf_evidence::SECEVENT_MEDIA_TYPE);
    assert!(matches!(
        receiver.receive(ct, None, t.as_bytes()),
        PushResponse::Accepted(_)
    ));
    // RFC 8935 section 2: answer as if the token had not been received before.
    let again = receiver.receive(ct, None, t.as_bytes());
    assert_eq!(again.status(), 202);
    assert!(matches!(again, PushResponse::AlreadyReceived(_)));
    Ok(())
}

#[test]
fn push_without_the_transmitter_credential_is_authentication_failed() -> TestResult {
    let (r, resolver) = evidence()?;
    let config = config()?;
    let ledger = MemoryJtiLedger::new();
    let receiver = PushReceiver {
        config: &config,
        resolver: &resolver,
        ledger: &ledger,
        authorization: Some("Bearer s3cret"),
    };
    let t = risk("p-auth", "HIGH", &r)?;
    let ct = Some(ssf_evidence::SECEVENT_MEDIA_TYPE);
    for given in [None, Some("Bearer wrong!"), Some("Bearer s3cre")] {
        let response = receiver.receive(ct, given, t.as_bytes());
        assert_eq!(response.status(), 400, "{given:?}");
        assert_eq!(push_body(&response)?["err"], "authentication_failed");
    }
    let response = receiver.receive(ct, Some("Bearer s3cret"), t.as_bytes());
    assert_eq!(response.status(), 202);
    Ok(())
}

#[test]
fn push_with_unreachable_evidence_is_503_and_retryable() -> TestResult {
    let (r, resolver) = evidence()?;
    let config = config()?;
    let ledger = MemoryJtiLedger::new();
    let empty = MapResolver::new();
    let t = risk("p-503", "HIGH", &r)?;
    let ct = Some(ssf_evidence::SECEVENT_MEDIA_TYPE);
    let down = PushReceiver {
        config: &config,
        resolver: &empty,
        ledger: &ledger,
        authorization: None,
    };
    let response = down.receive(ct, None, t.as_bytes());
    assert_eq!(response.status(), 503);
    let up = PushReceiver {
        resolver: &resolver,
        ..down
    };
    assert_eq!(up.receive(ct, None, t.as_bytes()).status(), 202);
    Ok(())
}

#[test]
fn every_code_maps_to_one_rfc_8935_error_code() {
    let expected = [
        (Code::SetMalformed, "invalid_request"),
        (Code::SetTyp, "invalid_request"),
        (Code::SetCrit, "invalid_request"),
        (Code::SetAlg, "invalid_key"),
        (Code::SetUnknownKey, "invalid_key"),
        (Code::SetSignature, "invalid_key"),
        (Code::SetIss, "invalid_issuer"),
        (Code::SetAud, "invalid_audience"),
        (Code::SetSubPresent, "invalid_request"),
        (Code::SetExpPresent, "invalid_request"),
        (Code::SetIat, "invalid_request"),
        (Code::SetJti, "invalid_request"),
        (Code::SetEvents, "invalid_request"),
        (Code::SetSubId, "invalid_request"),
        (Code::SetEventPayload, "invalid_request"),
        (Code::EvidenceAbsent, "invalid_request"),
        (Code::EvidenceClaimMalformed, "invalid_request"),
        (Code::EvidenceUnresolved, "invalid_request"),
        (Code::EvidenceDigestMismatch, "invalid_request"),
        (Code::EvidenceEnvelopeMalformed, "invalid_request"),
        (Code::EvidencePayloadType, "invalid_request"),
        (Code::EvidenceSignature, "invalid_request"),
        (Code::EvidenceStatement, "invalid_request"),
        (Code::EvidencePredicateType, "invalid_request"),
        (Code::EvidenceSubjectMismatch, "invalid_request"),
        (Code::SetJtiReplayed, "invalid_request"),
        (Code::SetJtiReused, "invalid_request"),
        (Code::SetJtiLedger, "invalid_request"),
        (Code::PushContentType, "invalid_request"),
        (Code::PushAuthentication, "authentication_failed"),
        (Code::PollRequest, "invalid_request"),
        (Code::PollResponse, "invalid_request"),
        (Code::PollSetKey, "invalid_request"),
        (Code::PollTransport, "invalid_request"),
    ];
    let allowed = [
        "invalid_request",
        "invalid_key",
        "invalid_issuer",
        "invalid_audience",
        "authentication_failed",
    ];
    let mut names = std::collections::BTreeSet::new();
    for (code, err) in expected {
        assert_eq!(code.set_error_code(), err, "{code}");
        assert!(allowed.contains(&err));
        assert!(names.insert(code.as_str()), "{code} named twice");
    }
}

// --- RFC 8936 poll ----------------------------------------------------------------

/// A transmitter's poll endpoint that answers with `body` and keeps every
/// request it was sent.
struct Scripted {
    body: Vec<u8>,
    seen: RefCell<Vec<PollRequest>>,
}

impl Scripted {
    fn new(response: &Value) -> TestResult<Self> {
        Ok(Self {
            body: serde_json::to_vec(response)?,
            seen: RefCell::new(Vec::new()),
        })
    }
}

impl PollTransport for Scripted {
    fn poll(&self, request: &PollRequest) -> Result<Vec<u8>, String> {
        self.seen.borrow_mut().push(request.clone());
        Ok(self.body.clone())
    }
}

#[test]
fn poll_response_without_sets_is_refused() {
    let got = PollResponse::from_json(br#"{"moreAvailable":true}"#);
    assert!(matches!(
        got,
        Err(Refusal {
            code: Code::PollResponse,
            ..
        })
    ));
}

#[test]
fn poll_response_parsing_is_strict() -> TestResult {
    for body in [
        r#"{"sets":{"a":7}}"#,
        r#"{"sets":[]}"#,
        r#"{"sets":{},"moreAvailable":"yes"}"#,
        r#"{"sets":{},"moreavailable":true}"#,
        r#"{"sets":{"a":"x.y.z"},"sets":{}}"#,
        r#"[]"#,
    ] {
        let got = PollResponse::from_json(body.as_bytes());
        assert!(
            matches!(
                got,
                Err(Refusal {
                    code: Code::PollResponse,
                    ..
                })
            ),
            "{body}: {got:?}"
        );
    }
    let ok = PollResponse::from_json(br#"{"sets":{}}"#)?;
    assert!(ok.sets.is_empty() && !ok.more_available);
    Ok(())
}

#[test]
fn poll_request_round_trips_and_parses_strictly() -> TestResult {
    let request = PollRequest::from_json(
        br#"{"ack":["a"],"setErrs":{"b":{"err":"invalid_key","description":"d"}},"maxEvents":0,"returnImmediately":true}"#,
    )?;
    assert_eq!(request.ack, vec!["a".to_string()]);
    assert_eq!(request.max_events, Some(0));
    assert_eq!(request.return_immediately, Some(true));
    assert_eq!(
        PollRequest::from_json(request.to_json()?.as_bytes())?,
        request
    );
    assert_eq!(PollRequest::default().to_json()?, "{}");
    for body in [
        r#"{"ack":"a"}"#,
        r#"{"maxEvents":-1}"#,
        r#"{"seterrs":{}}"#,
        r#"{"setErrs":{"b":{"err":"x"}}}"#,
        r#"{"ack":[],"ack":[]}"#,
    ] {
        let got = PollRequest::from_json(body.as_bytes());
        assert!(
            matches!(
                got,
                Err(Refusal {
                    code: Code::PollRequest,
                    ..
                })
            ),
            "{body}: {got:?}"
        );
    }
    Ok(())
}

#[test]
fn poll_once_acks_verified_tokens_and_reports_refused_ones() -> TestResult {
    let (r, resolver) = evidence()?;
    let ledger = MemoryJtiLedger::new();
    let good = credential_change("poll-good", "revoke", &r)?;
    let bad = credential_change("poll-bad", "rotate", &r)?;
    let transport = Scripted::new(&json!({
        "sets": {"poll-good": good, "poll-bad": bad}, "moreAvailable": true,
    }))?;
    let request = PollRequest {
        return_immediately: Some(true),
        max_events: Some(10),
        ..PollRequest::default()
    };
    let outcome = poll_once(&transport, &request, &config()?, &resolver, &ledger)?;
    assert_eq!(outcome.verified.len(), 1);
    assert!(outcome.more_available);
    assert_eq!(outcome.next.ack, vec!["poll-good".to_string()]);
    assert_eq!(
        outcome
            .next
            .set_errs
            .get("poll-bad")
            .map(|e| e.err.as_str()),
        Some("invalid_request")
    );
    assert_eq!(outcome.next.return_immediately, Some(true));
    assert_eq!(outcome.next.max_events, Some(10));
    assert_eq!(transport.seen.borrow().first(), Some(&request));

    // Delivered again: acknowledged again, not acted on again.
    let again = poll_once(&transport, &outcome.next, &config()?, &resolver, &ledger)?;
    assert!(again.verified.is_empty());
    assert_eq!(again.already_received, vec!["poll-good".to_string()]);
    assert_eq!(again.next.ack, vec!["poll-good".to_string()]);
    Ok(())
}

#[test]
fn poll_once_refuses_a_token_under_another_jti() -> TestResult {
    let (r, resolver) = evidence()?;
    let ledger = MemoryJtiLedger::new();
    let t = risk("real-jti", "HIGH", &r)?;
    let transport = Scripted::new(&json!({"sets": {"other-jti": t}}))?;
    let outcome = poll_once(
        &transport,
        &PollRequest::default(),
        &config()?,
        &resolver,
        &ledger,
    )?;
    assert!(outcome.verified.is_empty());
    assert!(outcome.next.ack.is_empty());
    assert!(outcome.next.set_errs.contains_key("other-jti"));
    // Nothing was recorded, so the token under its own jti still verifies.
    verify_set(&t, &config()?, &resolver, &ledger)?;
    Ok(())
}

#[test]
fn poll_once_defers_a_token_it_could_not_finish_checking() -> TestResult {
    let (r, _) = evidence()?;
    let t = risk("poll-late", "HIGH", &r)?;
    let transport = Scripted::new(&json!({"sets": {"poll-late": t}}))?;
    let outcome = poll_once(
        &transport,
        &PollRequest::default(),
        &config()?,
        &MapResolver::new(),
        &MemoryJtiLedger::new(),
    )?;
    assert!(outcome.next.ack.is_empty() && outcome.next.set_errs.is_empty());
    assert!(outcome.deferred.contains_key("poll-late"));
    Ok(())
}

#[test]
fn poll_once_reports_a_malformed_response_and_a_failed_transport() -> TestResult {
    let (_, resolver) = evidence()?;
    let malformed = Scripted::new(&json!({"moreAvailable": false}))?;
    let got = poll_once(
        &malformed,
        &PollRequest::default(),
        &config()?,
        &resolver,
        &MemoryJtiLedger::new(),
    );
    assert_eq!(code_of(got)?, Code::PollResponse);

    struct Down;
    impl PollTransport for Down {
        fn poll(&self, _: &PollRequest) -> Result<Vec<u8>, String> {
            Err("connection refused".into())
        }
    }
    let got = poll_once(
        &Down,
        &PollRequest::default(),
        &config()?,
        &resolver,
        &MemoryJtiLedger::new(),
    );
    assert_eq!(code_of(got)?, Code::PollTransport);
    Ok(())
}

#[test]
fn stream_verification_carries_no_revocation() -> TestResult {
    let key = SigningKey::ed25519_from_seed(&SEED)?.with_kid("tx");
    let claims: Map<String, Value> = match json!({
        "iss": ISSUER, "aud": AUDIENCE, "iat": NOW, "jti": "v-1",
        "sub_id": {"format": "opaque", "id": "stream-1"},
        "events": {VERIFICATION: {"state": "abc"}},
    }) {
        Value::Object(map) => map,
        _ => return Err("claims".into()),
    };
    let t = key.sign_compact(&serde_json::to_vec(&claims)?)?;
    let set = verify_set(&t, &config()?, &MapResolver::new(), &MemoryJtiLedger::new())?;
    assert_eq!(set.revocation, None);
    Ok(())
}

#[cfg(feature = "http")]
mod over_http {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use ssf_evidence::PollRequest;
    use ssf_evidence::http::HttpPoll;
    use ssf_evidence::poll::PollTransport;

    use super::TestResult;

    /// Serves one HTTP request with `status` and `body`, and sends back the
    /// request's Content-Type, Authorization and body.
    /// The Content-Type, Authorization and body of a request the server saw.
    type Seen = mpsc::Receiver<(String, String, String)>;

    fn serve_once(status: u16, body: &'static str) -> TestResult<(String, Seen)> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let url = format!("http://{}/poll", listener.local_addr()?);
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            let mut reader = BufReader::new(stream);
            let (mut ct, mut auth, mut len) = (String::new(), String::new(), 0usize);
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                let lower = line.to_ascii_lowercase();
                let value = line
                    .split_once(':')
                    .map(|(_, v)| v.trim().to_string())
                    .unwrap_or_default();
                if lower.starts_with("content-type:") {
                    ct = value;
                } else if lower.starts_with("authorization:") {
                    auth = value;
                } else if lower.starts_with("content-length:") {
                    len = value.parse().unwrap_or(0);
                }
            }
            let mut buf = vec![0u8; len];
            if reader.read_exact(&mut buf).is_err() {
                return;
            }
            let reply = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = reader.get_mut().write_all(reply.as_bytes());
            let _ = tx.send((ct, auth, String::from_utf8_lossy(&buf).into_owned()));
        });
        Ok((url, rx))
    }

    #[test]
    fn http_poll_posts_the_request_as_json_and_returns_the_200_body() -> TestResult {
        let (url, seen) = serve_once(200, r#"{"sets":{}}"#)?;
        let poll = HttpPoll::new(url, Duration::from_secs(5)).with_authorization("Bearer t");
        let request = PollRequest {
            ack: vec!["a".into()],
            return_immediately: Some(true),
            ..PollRequest::default()
        };
        let body = poll.poll(&request)?;
        assert_eq!(body, br#"{"sets":{}}"#);
        let (ct, auth, sent) = seen.recv_timeout(Duration::from_secs(5))?;
        assert_eq!(ct, "application/json");
        assert_eq!(auth, "Bearer t");
        assert_eq!(PollRequest::from_json(sent.as_bytes())?, request);
        Ok(())
    }

    #[test]
    fn http_poll_reports_a_non_200_as_an_error() -> TestResult {
        let (url, _seen) = serve_once(503, "{}")?;
        let poll = HttpPoll::new(url, Duration::from_secs(5));
        assert!(poll.poll(&PollRequest::default()).is_err());
        Ok(())
    }
}
