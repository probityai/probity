//! The transmitting side: decide which event a signal becomes, sign it, and
//! either log it (monitor mode) or queue it for delivery (live mode).

use serde_json::{Map, Value, json};

use crate::delivery::{Outbox, Push, PushOutcome, RetryPolicy};
use crate::error::Error;
use crate::evidence::{EVIDENCE_REF_CLAIM, EvidenceRef, EvidenceTrust, Resolver, verify_evidence};
use crate::jws::SigningKey;
use crate::receiver::{RISK_LEVEL_CHANGE, SESSION_REVOKED, VERIFICATION};
use crate::subject::{Principal, RiskLevel, Subject};

/// Whether events leave the transmitter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Events are computed, signed and logged, and nothing is sent.
    Monitor,
    /// Events are queued for delivery.
    Live,
}

/// What the receiver has authorized this transmitter to ask of it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Capabilities {
    /// The receiver lets this transmitter revoke sessions. Without it, a
    /// revocation request is sent as a high risk level instead.
    pub session_revoke: bool,
}

/// The stream an event goes out on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stream {
    /// The stream's identifier, used by stream verification.
    pub stream_id: String,
    /// The receiver's `aud` value.
    pub audience: String,
    /// The stream's `events_delivered`.
    pub events_delivered: Vec<String>,
}

/// What a signal asks the receiver to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Raise (or lower) the subject's risk level.
    ChangeRisk {
        /// Which party the level describes.
        principal: Principal,
        /// The new level.
        current: RiskLevel,
        /// The level before, when known.
        previous: Option<RiskLevel>,
        /// Why.
        reason: Option<String>,
    },
    /// Revoke the subject's session.
    RevokeSession {
        /// The administrative reason, in English (required by the CAEP
        /// interoperability profile).
        reason_admin: String,
    },
}

/// One decision to tell the receiver something, with the evidence behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signal {
    /// Who it is about.
    pub subject: Subject,
    /// What is asked.
    pub action: Action,
    /// The evidence the decision rests on.
    pub evidence: EvidenceRef,
    /// The `txn` shared by tokens from one underlying cause.
    pub txn: Option<String>,
    /// When the underlying event happened.
    pub event_timestamp: Option<u64>,
}

/// Which event a signal became.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The event the signal asked for.
    AsRequested {
        /// Its type URI.
        event_type: String,
    },
    /// A revocation sent as a high risk level, because the stream lacks the
    /// capability or does not deliver session-revoked.
    Downgraded {
        /// Its type URI.
        event_type: String,
    },
    /// Nothing is sent: the stream delivers no event the signal maps to.
    Suppressed {
        /// Why.
        reason: String,
    },
}

/// One computed event, as monitor mode records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorRecord {
    /// When it was computed.
    pub at: u64,
    /// The token's `jti`, or `None` when suppressed.
    pub jti: Option<String>,
    /// What the signal became.
    pub decision: Decision,
    /// The signed token live mode would have queued.
    pub token: Option<String>,
}

/// What [`Transmitter::emit`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Emission {
    /// Monitor mode: the event was logged and not sent.
    Monitored(MonitorRecord),
    /// Live mode: the token was queued under this `jti`.
    Queued {
        /// The token's `jti`.
        jti: String,
        /// What the signal became.
        decision: Decision,
    },
    /// Nothing was produced.
    Suppressed(Decision),
}

/// Produces a fresh `jti` for every token.
pub trait JtiSource {
    /// The next `jti`.
    fn next_jti(&mut self) -> String;
}

/// 128 random bits, hex encoded.
#[derive(Debug, Default)]
pub struct RandomJti;

impl JtiSource for RandomJti {
    fn next_jti(&mut self) -> String {
        let mut bytes = [0u8; 16];
        // SystemRandom fails only when the operating system's generator is
        // unavailable; a counter would then repeat across restarts, so the
        // failure is surfaced as an empty jti, which every receiver refuses.
        if ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes).is_err() {
            return String::new();
        }
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// An SSF transmitter for one stream.
pub struct Transmitter {
    issuer: String,
    key: SigningKey,
    stream: Stream,
    mode: Mode,
    capabilities: Capabilities,
    jti: Box<dyn JtiSource + Send>,
    preflight: Option<(Box<dyn Resolver + Send + Sync>, EvidenceTrust)>,
    monitor_log: Vec<MonitorRecord>,
    outbox: Outbox,
}

impl std::fmt::Debug for Transmitter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transmitter")
            .field("issuer", &self.issuer)
            .field("stream", &self.stream)
            .field("mode", &self.mode)
            .field("capabilities", &self.capabilities)
            .finish_non_exhaustive()
    }
}

impl Transmitter {
    /// A transmitter that starts in monitor mode with no capabilities.
    pub fn new(issuer: impl Into<String>, key: SigningKey, stream: Stream) -> Self {
        Self {
            issuer: issuer.into(),
            key,
            stream,
            mode: Mode::Monitor,
            capabilities: Capabilities::default(),
            jti: Box::new(RandomJti),
            preflight: None,
            monitor_log: Vec::new(),
            outbox: Outbox::new(RetryPolicy::default()),
        }
    }

    /// Sets the capabilities the receiver granted.
    #[must_use]
    pub fn with_capabilities(mut self, capabilities: Capabilities) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Sets the `jti` source.
    #[must_use]
    pub fn with_jti_source(mut self, source: Box<dyn JtiSource + Send>) -> Self {
        self.jti = source;
        self
    }

    /// Sets the retry policy of an empty outbox.
    #[must_use]
    pub fn with_retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.outbox = Outbox::new(policy);
        self
    }

    /// Checks every signal's own evidence before signing it, so the
    /// transmitter never emits an event a receiver will refuse.
    #[must_use]
    pub fn with_preflight(
        mut self,
        resolver: Box<dyn Resolver + Send + Sync>,
        trust: EvidenceTrust,
    ) -> Self {
        self.preflight = Some((resolver, trust));
        self
    }

    /// Switches mode. Events logged in monitor mode are never sent later.
    pub fn set_mode(&mut self, mode: Mode) {
        self.mode = mode;
    }

    /// The current mode.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Everything monitor mode recorded.
    pub fn monitor_log(&self) -> &[MonitorRecord] {
        &self.monitor_log
    }

    /// The delivery queue.
    pub fn outbox(&self) -> &Outbox {
        &self.outbox
    }

    /// The delivery queue, to tick and replay.
    pub fn outbox_mut(&mut self) -> &mut Outbox {
        &mut self.outbox
    }

    fn delivers(&self, event_type: &str) -> bool {
        self.stream.events_delivered.iter().any(|e| e == event_type)
    }

    /// Which event `action` becomes on this stream.
    pub fn decide(&self, action: &Action) -> Decision {
        match action {
            Action::ChangeRisk { .. } if self.delivers(RISK_LEVEL_CHANGE) => {
                Decision::AsRequested {
                    event_type: RISK_LEVEL_CHANGE.into(),
                }
            }
            Action::ChangeRisk { .. } => Decision::Suppressed {
                reason: "the stream does not deliver risk-level-change".into(),
            },
            Action::RevokeSession { .. }
                if self.capabilities.session_revoke && self.delivers(SESSION_REVOKED) =>
            {
                Decision::AsRequested {
                    event_type: SESSION_REVOKED.into(),
                }
            }
            Action::RevokeSession { .. } if self.delivers(RISK_LEVEL_CHANGE) => {
                Decision::Downgraded {
                    event_type: RISK_LEVEL_CHANGE.into(),
                }
            }
            Action::RevokeSession { .. } => Decision::Suppressed {
                reason: "the stream delivers neither session-revoked nor risk-level-change".into(),
            },
        }
    }

    fn event_object(signal: &Signal, decision: &Decision) -> Map<String, Value> {
        let mut event = Map::new();
        match (&signal.action, decision) {
            (Action::RevokeSession { reason_admin }, Decision::AsRequested { .. }) => {
                event.insert("initiating_entity".into(), json!("policy"));
                event.insert("reason_admin".into(), json!({"en": reason_admin}));
            }
            (Action::RevokeSession { reason_admin }, _) => {
                let principal = if signal.subject.session.is_some() {
                    Principal::Session
                } else if signal.subject.agent.is_some() {
                    Principal::Agent
                } else {
                    Principal::User
                };
                event.insert("principal".into(), json!(principal.as_str()));
                event.insert("current_level".into(), json!(RiskLevel::High.as_str()));
                event.insert("risk_reason".into(), json!(reason_admin));
                event.insert("initiating_entity".into(), json!("policy"));
            }
            (
                Action::ChangeRisk {
                    principal,
                    current,
                    previous,
                    reason,
                },
                _,
            ) => {
                event.insert("principal".into(), json!(principal.as_str()));
                event.insert("current_level".into(), json!(current.as_str()));
                if let Some(previous) = previous {
                    event.insert("previous_level".into(), json!(previous.as_str()));
                }
                if let Some(reason) = reason {
                    event.insert("risk_reason".into(), json!(reason));
                }
                event.insert("initiating_entity".into(), json!("policy"));
            }
        }
        if let Some(ts) = signal.event_timestamp {
            event.insert("event_timestamp".into(), json!(ts));
        }
        event.insert(EVIDENCE_REF_CLAIM.into(), signal.evidence.to_value());
        event
    }

    fn sign_event(
        &mut self,
        event_type: &str,
        event: Map<String, Value>,
        sub_id: Value,
        txn: Option<&str>,
        now: u64,
    ) -> Result<(String, String), Error> {
        let jti = self.jti.next_jti();
        if jti.is_empty() {
            return Err(Error::Input("the jti source produced an empty jti".into()));
        }
        let mut events = Map::new();
        events.insert(event_type.into(), Value::Object(event));
        let mut claims = Map::new();
        claims.insert("iss".into(), json!(self.issuer));
        claims.insert("aud".into(), json!(self.stream.audience));
        claims.insert("iat".into(), json!(now));
        claims.insert("jti".into(), json!(jti));
        claims.insert("sub_id".into(), sub_id);
        claims.insert("events".into(), Value::Object(events));
        if let Some(txn) = txn {
            claims.insert("txn".into(), json!(txn));
        }
        let payload =
            serde_json::to_vec(&Value::Object(claims)).map_err(|e| Error::Input(e.to_string()))?;
        Ok((jti, self.key.sign_compact(&payload)?))
    }

    /// Turns a signal into an event: logged in monitor mode, queued in live mode.
    pub fn emit(&mut self, signal: &Signal, now: u64) -> Result<Emission, Error> {
        let decision = self.decide(&signal.action);
        let event_type = match &decision {
            Decision::AsRequested { event_type } | Decision::Downgraded { event_type } => {
                event_type.clone()
            }
            Decision::Suppressed { .. } => {
                if self.mode == Mode::Monitor {
                    self.monitor_log.push(MonitorRecord {
                        at: now,
                        jti: None,
                        decision: decision.clone(),
                        token: None,
                    });
                }
                return Ok(Emission::Suppressed(decision));
            }
        };
        let sub_id = signal.subject.to_sub_id()?;
        if let Some((resolver, trust)) = &self.preflight {
            verify_evidence(&signal.evidence, &sub_id, resolver.as_ref(), trust)
                .map_err(Error::Preflight)?;
        }
        let event = Self::event_object(signal, &decision);
        let (jti, token) =
            self.sign_event(&event_type, event, sub_id, signal.txn.as_deref(), now)?;
        match self.mode {
            Mode::Monitor => {
                let record = MonitorRecord {
                    at: now,
                    jti: Some(jti),
                    decision,
                    token: Some(token),
                };
                self.monitor_log.push(record.clone());
                Ok(Emission::Monitored(record))
            }
            Mode::Live => {
                self.outbox.enqueue(jti.clone(), token)?;
                Ok(Emission::Queued { jti, decision })
            }
        }
    }

    /// The SSF stream verification token carrying `state`.
    pub fn verification_token(&mut self, state: &str, now: u64) -> Result<String, Error> {
        let mut event = Map::new();
        event.insert("state".into(), json!(state));
        let sub_id = json!({"format": "opaque", "id": self.stream.stream_id});
        Ok(self.sign_event(VERIFICATION, event, sub_id, None, now)?.1)
    }

    /// Test Connection: sends a verification event at once, in either mode,
    /// and reports what the receiver answered. Nothing is queued.
    pub fn test_connection(
        &mut self,
        push: &dyn Push,
        state: &str,
        now: u64,
    ) -> Result<PushOutcome, Error> {
        let token = self.verification_token(state, now)?;
        Ok(push.push(&token))
    }
}
