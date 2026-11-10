//! Monitor mode, the capability gate, the evidence preflight, the delivery
//! state machine, and push delivery to a real local HTTP receiver.

use std::cell::RefCell;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use dsse::{Ed25519Signer, Signer};
use serde_json::{Value, json};
use ssf_evidence::delivery::{Entry, transition};
use ssf_evidence::evidence::{IN_TOTO_PAYLOAD_TYPE, STATEMENT_TYPE};
use ssf_evidence::http::HttpPush;
use ssf_evidence::transmitter::JtiSource;
use ssf_evidence::{
    Action, Capabilities, DeadLetterReason, Decision, DeliveryState, Emission, Error,
    EvidencePolicy, EvidenceRef, EvidenceTrust, MapResolver, Mode, Outbox, Principal, Push,
    PushOutcome, RISK_LEVEL_CHANGE, ReceiverConfig, RetryPolicy, RiskLevel, SESSION_REVOKED,
    Signal, SigningKey, Stream, Subject, SubjectId, Transmitter, verify_set,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const ISSUER: &str = "https://transmitter.example.test/";
const AUDIENCE: &str = "https://receiver.example.test/ssf";
const SEED: [u8; 32] = [0x44; 32];
const EVIDENCE_SEED: [u8; 32] = [0x55; 32];
const URI: &str = "https://evidence.example.test/e/1.dsse.json";

struct Counter(u32);

impl JtiSource for Counter {
    fn next_jti(&mut self) -> String {
        self.0 += 1;
        format!("jti-{}", self.0)
    }
}

fn subject() -> Subject {
    Subject {
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
}

fn evidence(seed: &[u8; 32]) -> TestResult<(EvidenceRef, MapResolver)> {
    let sub_id = subject().to_sub_id()?;
    let statement = serde_json::to_vec(&json!({
        "_type": STATEMENT_TYPE,
        "subject": [ssf_evidence::subject_descriptor(&sub_id)?],
        "predicateType": "https://example.test/predicate/v1/agent-decision",
        "predicate": {},
    }))?;
    let signer = Ed25519Signer::from_bytes(seed)?.with_key_id("ev");
    let signers: [&dyn Signer; 1] = [&signer];
    let bytes = dsse::sign_with(IN_TOTO_PAYLOAD_TYPE, &statement, &signers)?.to_json()?;
    let mut resolver = MapResolver::new();
    resolver.insert(URI, bytes.clone());
    Ok((EvidenceRef::for_envelope(&bytes, URI), resolver))
}

fn trust() -> TestResult<EvidenceTrust> {
    let verifier = Ed25519Signer::from_bytes(&EVIDENCE_SEED)?
        .with_key_id("ev")
        .verifier();
    Ok(EvidenceTrust {
        keys: vec![Box::new(verifier)],
        threshold: 1,
        predicate_types: None,
    })
}

fn stream(events: &[&str]) -> Stream {
    Stream {
        stream_id: "stream-1".into(),
        audience: AUDIENCE.into(),
        events_delivered: events.iter().map(|e| (*e).to_string()).collect(),
    }
}

fn transmitter(events: &[&str]) -> TestResult<Transmitter> {
    let key = SigningKey::ed25519_from_seed(&SEED)?.with_kid("tx");
    Ok(Transmitter::new(ISSUER, key, stream(events)).with_jti_source(Box::new(Counter(0))))
}

fn revoke(evidence: EvidenceRef) -> Signal {
    Signal {
        subject: subject(),
        action: Action::RevokeSession {
            reason_admin: "outside grant".into(),
        },
        evidence,
        txn: None,
        event_timestamp: None,
    }
}

fn receiver() -> TestResult<ReceiverConfig> {
    let key = SigningKey::ed25519_from_seed(&SEED)?.with_kid("tx");
    Ok(ReceiverConfig {
        issuer: ISSUER.into(),
        audience: AUDIENCE.into(),
        keys: vec![key.ed25519_verifying_key().ok_or("key")?],
        evidence: trust()?,
        evidence_policy: EvidencePolicy::Required,
    })
}

#[test]
fn monitor_mode_signs_and_logs_but_queues_nothing() -> TestResult {
    let (r, resolver) = evidence(&EVIDENCE_SEED)?;
    let mut tx = transmitter(&[RISK_LEVEL_CHANGE, SESSION_REVOKED])?;
    assert_eq!(tx.mode(), Mode::Monitor);
    let Emission::Monitored(record) = tx.emit(&revoke(r.clone()), 100)? else {
        return Err("monitor mode did not log".into());
    };
    assert!(tx.outbox().entries().is_empty());
    assert_eq!(tx.monitor_log().len(), 1);
    // The logged token is exactly what live mode would send, and it verifies.
    let token = record.token.ok_or("no token")?;
    assert_eq!(
        verify_set(&token, &receiver()?, &resolver)?.event_type,
        RISK_LEVEL_CHANGE
    );
    tx.set_mode(Mode::Live);
    assert!(
        tx.outbox().entries().is_empty(),
        "switching mode sends nothing logged earlier"
    );
    assert!(matches!(tx.emit(&revoke(r), 101)?, Emission::Queued { .. }));
    assert_eq!(tx.outbox().entries().len(), 1);
    Ok(())
}

#[test]
fn session_revoked_needs_the_capability() -> TestResult {
    let (r, _) = evidence(&EVIDENCE_SEED)?;
    let both = [RISK_LEVEL_CHANGE, SESSION_REVOKED];
    let without = transmitter(&both)?;
    assert_eq!(
        without.decide(&revoke(r.clone()).action),
        Decision::Downgraded {
            event_type: RISK_LEVEL_CHANGE.into()
        }
    );
    let with = transmitter(&both)?.with_capabilities(Capabilities {
        session_revoke: true,
    });
    assert_eq!(
        with.decide(&revoke(r.clone()).action),
        Decision::AsRequested {
            event_type: SESSION_REVOKED.into()
        }
    );
    let only_revoked = transmitter(&[SESSION_REVOKED])?.with_capabilities(Capabilities {
        session_revoke: true,
    });
    let change = Action::ChangeRisk {
        principal: Principal::Agent,
        current: RiskLevel::High,
        previous: None,
        reason: None,
    };
    assert!(matches!(
        only_revoked.decide(&change),
        Decision::Suppressed { .. }
    ));
    let nothing = transmitter(&[])?;
    assert!(matches!(
        nothing.decide(&revoke(r).action),
        Decision::Suppressed { .. }
    ));
    Ok(())
}

#[test]
fn preflight_refuses_a_signal_whose_evidence_fails() -> TestResult {
    let (r, resolver) = evidence(&[0x66; 32])?;
    let mut tx = transmitter(&[RISK_LEVEL_CHANGE])?.with_preflight(Box::new(resolver), trust()?);
    match tx.emit(&revoke(r), 1) {
        Err(Error::Preflight(refusal)) => assert_eq!(refusal.code.as_str(), "evidence.signature"),
        other => return Err(format!("expected a preflight refusal, got {other:?}").into()),
    }
    assert!(tx.monitor_log().is_empty());
    Ok(())
}

fn entry() -> Entry {
    Entry {
        jti: "j".into(),
        token: "t".into(),
        state: DeliveryState::Pending,
        attempts: 0,
        last_error: None,
    }
}

#[test]
fn transition_covers_every_outcome() {
    let policy = RetryPolicy {
        max_attempts: 3,
        base_delay_secs: 10,
        max_delay_secs: 25,
    };
    let ok = transition(&entry(), &PushOutcome::Accepted, 5, &policy);
    assert_eq!(ok.state, DeliveryState::Delivered { at: 5 });

    let refused = PushOutcome::Rejected {
        err: "invalid_audience".into(),
        description: "no".into(),
    };
    let dead = transition(&entry(), &refused, 5, &policy);
    assert_eq!(
        dead.state,
        DeliveryState::DeadLettered {
            at: 5,
            reason: DeadLetterReason::Refused {
                err: "invalid_audience".into()
            }
        }
    );

    let stale_key = PushOutcome::Rejected {
        err: "invalid_key".into(),
        description: "rotate".into(),
    };
    let transient = PushOutcome::Transient {
        status: Some(503),
        detail: "busy".into(),
    };
    let one = transition(&entry(), &stale_key, 0, &policy);
    assert_eq!(one.state, DeliveryState::Retrying { next_at: 10 });
    let two = transition(&one, &transient, 10, &policy);
    assert_eq!(
        two.state,
        DeliveryState::Retrying { next_at: 30 },
        "the delay doubles, capped at 25"
    );
    let three = transition(&two, &transient, 30, &policy);
    assert!(matches!(
        three.state,
        DeliveryState::DeadLettered {
            reason: DeadLetterReason::AttemptsExhausted { .. },
            ..
        }
    ));
}

struct Script(RefCell<Vec<PushOutcome>>);

impl Push for Script {
    fn push(&self, _token: &str) -> PushOutcome {
        let mut queue = self.0.borrow_mut();
        if queue.is_empty() {
            PushOutcome::Accepted
        } else {
            queue.remove(0)
        }
    }
}

#[test]
fn outbox_retries_dead_letters_replays_and_survives_a_restart() -> TestResult {
    let policy = RetryPolicy {
        max_attempts: 2,
        base_delay_secs: 10,
        max_delay_secs: 100,
    };
    let mut outbox = Outbox::new(policy);
    outbox.enqueue("a", "token-a")?;
    outbox.enqueue("b", "token-b")?;
    assert!(
        outbox.enqueue("a", "again").is_err(),
        "one jti names one token"
    );
    let busy = || PushOutcome::Transient {
        status: None,
        detail: "connection refused".into(),
    };
    let script = Script(RefCell::new(vec![busy(), busy()]));
    let report = outbox.tick(0, &script);
    assert_eq!(report.retrying, vec!["a".to_string(), "b".to_string()]);
    assert!(
        outbox.tick(5, &script).delivered.is_empty(),
        "nothing is due before the backoff"
    );
    let script = Script(RefCell::new(vec![busy()]));
    let report = outbox.tick(10, &script);
    assert_eq!(
        (report.dead_lettered, report.delivered),
        (vec!["a".to_string()], vec!["b".to_string()])
    );

    let restored = Outbox::from_json(&outbox.to_json()?)?;
    assert_eq!(restored, outbox);
    let mut outbox = restored;
    assert!(
        outbox.replay("b").is_err(),
        "only a dead letter is replayed"
    );
    outbox.replay("a")?;
    let report = outbox.tick(11, &Script(RefCell::new(vec![])));
    assert_eq!(report.delivered, vec!["a".to_string()]);
    assert_eq!(
        outbox.get("a").map(|e| e.token.as_str()),
        Some("token-a"),
        "the same bytes go out again"
    );
    assert_eq!(outbox.dead_letters().count(), 0);
    Ok(())
}

/// A one-thread HTTP receiver that answers each request with the next status
/// in `script` (202 when it runs out), verifying the pushed token on 202.
fn serve(script: Vec<u16>, count: usize) -> TestResult<(String, mpsc::Receiver<(String, String)>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let url = format!("http://{}/ssf/push", listener.local_addr()?);
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut script = script.into_iter();
        for stream in listener.incoming().take(count) {
            let Ok(mut stream) = stream else { return };
            let mut reader = BufReader::new(match stream.try_clone() {
                Ok(s) => s,
                Err(_) => return,
            });
            let (mut content_type, mut length) = (String::new(), 0usize);
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() || line == "\r\n" || line.is_empty() {
                    break;
                }
                let lower = line.to_ascii_lowercase();
                if let Some(v) = lower.strip_prefix("content-type:") {
                    content_type = v.trim().to_string();
                }
                if let Some(v) = lower.strip_prefix("content-length:") {
                    length = v.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0; length];
            if reader.read_exact(&mut body).is_err() {
                return;
            }
            let _ = tx.send((content_type, String::from_utf8_lossy(&body).into_owned()));
            let status = script.next().unwrap_or(202);
            let response = match status {
                202 => "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_string(),
                400 => {
                    let b = r#"{"err":"invalid_audience","description":"not for us"}"#;
                    format!(
                        "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Language: en\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
                        b.len()
                    )
                }
                s => format!(
                    "HTTP/1.1 {s} Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                ),
            };
            let _ = stream.write_all(response.as_bytes());
        }
    });
    Ok((url, rx))
}

#[test]
fn live_delivery_over_http_retries_then_lands() -> TestResult {
    let (r, resolver) = evidence(&EVIDENCE_SEED)?;
    let (url, seen) = serve(vec![503, 202], 2)?;
    let mut tx = transmitter(&[RISK_LEVEL_CHANGE])?.with_retry_policy(RetryPolicy {
        max_attempts: 5,
        base_delay_secs: 1,
        max_delay_secs: 1,
    });
    tx.set_mode(Mode::Live);
    tx.emit(&revoke(r), 1)?;
    let push = HttpPush::new(url, Duration::from_secs(5));
    assert_eq!(tx.outbox_mut().tick(1, &push).retrying.len(), 1);
    assert_eq!(tx.outbox_mut().tick(2, &push).delivered.len(), 1);
    let (content_type, first) = seen.recv_timeout(Duration::from_secs(5))?;
    let (_, second) = seen.recv_timeout(Duration::from_secs(5))?;
    assert_eq!(content_type, "application/secevent+jwt");
    assert_eq!(first, second, "a retry sends the same bytes");
    assert_eq!(verify_set(&second, &receiver()?, &resolver)?.jti, "jti-1");
    Ok(())
}

#[test]
fn test_connection_reports_a_refusal_and_queues_nothing() -> TestResult {
    let (r, _) = evidence(&EVIDENCE_SEED)?;
    let (url, seen) = serve(vec![400, 202], 2)?;
    let mut tx = transmitter(&[RISK_LEVEL_CHANGE])?;
    let push = HttpPush::new(url, Duration::from_secs(5));
    match tx.test_connection(&push, "probe", 1)? {
        PushOutcome::Rejected { err, .. } => assert_eq!(err, "invalid_audience"),
        other => return Err(format!("expected a refusal, got {other:?}").into()),
    }
    let (_, verification) = seen.recv_timeout(Duration::from_secs(5))?;
    let claims: Value = serde_json::from_slice(&base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        verification.split('.').nth(1).ok_or("payload")?,
    )?)?;
    assert_eq!(claims.pointer("/sub_id/id"), Some(&json!("stream-1")));
    assert!(
        tx.outbox().entries().is_empty(),
        "test connection queues nothing"
    );
    tx.set_mode(Mode::Live);
    tx.emit(&revoke(r), 2)?;
    assert_eq!(tx.outbox_mut().tick(2, &push).delivered.len(), 1);
    Ok(())
}
