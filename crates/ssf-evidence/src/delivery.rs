//! At-least-once push delivery (RFC 8935) as an explicit state machine.
//!
//! Every token enters the outbox `Pending`. A push either lands (`Delivered`),
//! fails in a way a later attempt can fix (`Retrying`, with a backoff), or is
//! refused in a way no retry of the same bytes can fix (`DeadLettered`). A
//! token that exhausts its attempts is dead-lettered too. A dead letter is
//! replayed by moving it back to `Pending`: the same bytes and the same `jti`
//! go out again, and the receiver deduplicates on `jti`. Time is passed in, so
//! the machine is deterministic and its whole state serialises for a restart.

use serde::{Deserialize, Serialize};

use crate::error::Error;

/// What one push attempt returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushOutcome {
    /// HTTP 202: the receiver accepted the token.
    Accepted,
    /// HTTP 400 with a Security Event Token Error Code.
    Rejected {
        /// The `err` member.
        err: String,
        /// The `description` member.
        description: String,
    },
    /// No answer, a 5xx, a 429, a 401 or 403, or any other response that does
    /// not refuse the token itself.
    Transient {
        /// The HTTP status, when there was one.
        status: Option<u16>,
        /// What happened.
        detail: String,
    },
}

/// Sends one token to a receiver.
pub trait Push {
    /// Pushes `token` and reports the outcome.
    fn push(&self, token: &str) -> PushOutcome;
}

/// Why a token was dead-lettered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DeadLetterReason {
    /// The receiver refused the token with this error code.
    Refused {
        /// The `err` member of the receiver's answer.
        err: String,
    },
    /// Every allowed attempt failed transiently.
    AttemptsExhausted {
        /// The last failure.
        last: String,
    },
}

/// Where a token stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DeliveryState {
    /// Waiting for its first attempt, or replayed.
    Pending,
    /// The last attempt failed transiently; the next is due at `next_at`.
    Retrying {
        /// When the next attempt is due, in seconds since the epoch.
        next_at: u64,
    },
    /// The receiver accepted it.
    Delivered {
        /// When.
        at: u64,
    },
    /// No further attempt will be made unless it is replayed.
    DeadLettered {
        /// When.
        at: u64,
        /// Why.
        reason: DeadLetterReason,
    },
}

/// How often and how patiently to retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryPolicy {
    /// Attempts before a transiently failing token is dead-lettered.
    pub max_attempts: u32,
    /// The delay after the first failure, in seconds; it doubles per failure.
    pub base_delay_secs: u64,
    /// The longest delay, in seconds.
    pub max_delay_secs: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 8,
            base_delay_secs: 5,
            max_delay_secs: 3600,
        }
    }
}

impl RetryPolicy {
    fn delay_after(&self, attempts: u32) -> u64 {
        let shift = attempts.saturating_sub(1).min(32);
        self.base_delay_secs
            .saturating_mul(1u64 << shift)
            .min(self.max_delay_secs)
    }
}

/// The RFC 8935 error codes a later attempt can cure: a key the receiver has
/// not fetched yet, and an expired access token the transmitter will refresh.
pub const RETRYABLE_ERRORS: [&str; 2] = ["invalid_key", "authentication_failed"];

/// One token in the outbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// The token's `jti`.
    pub jti: String,
    /// The compact token, byte for byte what every attempt sends.
    pub token: String,
    /// Where it stands.
    pub state: DeliveryState,
    /// Attempts since it was enqueued or last replayed.
    pub attempts: u32,
    /// The last failure, if any.
    pub last_error: Option<String>,
}

/// The next state of `entry` after `outcome` at `now`.
pub fn transition(entry: &Entry, outcome: &PushOutcome, now: u64, policy: &RetryPolicy) -> Entry {
    let mut next = entry.clone();
    next.attempts = entry.attempts.saturating_add(1);
    let failure = match outcome {
        PushOutcome::Accepted => {
            next.state = DeliveryState::Delivered { at: now };
            next.last_error = None;
            return next;
        }
        PushOutcome::Rejected { err, description } => {
            let text = format!("400 {err}: {description}");
            if !RETRYABLE_ERRORS.contains(&err.as_str()) {
                next.state = DeliveryState::DeadLettered {
                    at: now,
                    reason: DeadLetterReason::Refused { err: err.clone() },
                };
                next.last_error = Some(text);
                return next;
            }
            text
        }
        PushOutcome::Transient { status, detail } => match status {
            Some(code) => format!("{code}: {detail}"),
            None => detail.clone(),
        },
    };
    next.state = if next.attempts >= policy.max_attempts {
        DeliveryState::DeadLettered {
            at: now,
            reason: DeadLetterReason::AttemptsExhausted {
                last: failure.clone(),
            },
        }
    } else {
        DeliveryState::Retrying {
            next_at: now.saturating_add(policy.delay_after(next.attempts)),
        }
    };
    next.last_error = Some(failure);
    next
}

/// What one pass over the outbox did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TickReport {
    /// Tokens accepted in this pass.
    pub delivered: Vec<String>,
    /// Tokens scheduled for another attempt.
    pub retrying: Vec<String>,
    /// Tokens dead-lettered in this pass.
    pub dead_lettered: Vec<String>,
}

/// The delivery queue for one stream.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outbox {
    entries: Vec<Entry>,
    policy: RetryPolicy,
}

impl Outbox {
    /// An empty outbox.
    pub fn new(policy: RetryPolicy) -> Self {
        Self {
            entries: Vec::new(),
            policy,
        }
    }

    /// Queues a token. A `jti` already in the outbox is refused: one `jti`
    /// names one token.
    pub fn enqueue(
        &mut self,
        jti: impl Into<String>,
        token: impl Into<String>,
    ) -> Result<(), Error> {
        let jti = jti.into();
        if self.entries.iter().any(|e| e.jti == jti) {
            return Err(Error::Delivery(format!("jti {jti} is already queued")));
        }
        self.entries.push(Entry {
            jti,
            token: token.into(),
            state: DeliveryState::Pending,
            attempts: 0,
            last_error: None,
        });
        Ok(())
    }

    /// Every entry, in the order it was enqueued.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The entry for `jti`.
    pub fn get(&self, jti: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.jti == jti)
    }

    /// The dead-lettered entries.
    pub fn dead_letters(&self) -> impl Iterator<Item = &Entry> {
        self.entries
            .iter()
            .filter(|e| matches!(e.state, DeliveryState::DeadLettered { .. }))
    }

    /// Attempts every entry due at `now`, in enqueue order.
    pub fn tick(&mut self, now: u64, push: &dyn Push) -> TickReport {
        let mut report = TickReport::default();
        for entry in &mut self.entries {
            let due = match entry.state {
                DeliveryState::Pending => true,
                DeliveryState::Retrying { next_at } => next_at <= now,
                DeliveryState::Delivered { .. } | DeliveryState::DeadLettered { .. } => false,
            };
            if !due {
                continue;
            }
            *entry = transition(entry, &push.push(&entry.token), now, &self.policy);
            let bucket = match entry.state {
                DeliveryState::Delivered { .. } => &mut report.delivered,
                DeliveryState::Retrying { .. } => &mut report.retrying,
                _ => &mut report.dead_lettered,
            };
            bucket.push(entry.jti.clone());
        }
        report
    }

    /// Moves a dead letter back to `Pending` with its attempt count reset.
    pub fn replay(&mut self, jti: &str) -> Result<(), Error> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.jti == jti)
            .ok_or_else(|| Error::Delivery(format!("jti {jti} is not in the outbox")))?;
        if !matches!(entry.state, DeliveryState::DeadLettered { .. }) {
            return Err(Error::Delivery(format!("jti {jti} is not dead-lettered")));
        }
        entry.state = DeliveryState::Pending;
        entry.attempts = 0;
        Ok(())
    }

    /// Replays every dead letter, returning their `jti`s.
    pub fn replay_all(&mut self) -> Vec<String> {
        let mut replayed = Vec::new();
        for entry in &mut self.entries {
            if matches!(entry.state, DeliveryState::DeadLettered { .. }) {
                entry.state = DeliveryState::Pending;
                entry.attempts = 0;
                replayed.push(entry.jti.clone());
            }
        }
        replayed
    }

    /// The outbox as JSON, for durable storage between runs.
    pub fn to_json(&self) -> Result<String, Error> {
        serde_json::to_string(self).map_err(|e| Error::Delivery(e.to_string()))
    }

    /// An outbox restored from [`Outbox::to_json`].
    pub fn from_json(text: &str) -> Result<Self, Error> {
        serde_json::from_str(text).map_err(|e| Error::Delivery(e.to_string()))
    }
}
