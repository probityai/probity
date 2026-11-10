//! Security Event Tokens for the OpenID Shared Signals Framework whose CAEP
//! events carry a reference to signed evidence.
//!
//! A transmitter turns a decision about an agent (raise the risk level, revoke
//! the session) into a CAEP event whose event object carries the claim
//! [`EVIDENCE_REF_CLAIM`]: the SHA-256 digest and retrieval URI of a DSSE
//! envelope holding an in-toto Statement about the same subject. A receiver
//! built on [`verify_set`] refuses any event whose evidence does not resolve,
//! does not hash to the digest, does not verify under a trusted key, or names a
//! different subject. The receiving identity provider then acts on evidence
//! anyone can check, not on the transmitter's word.
//!
//! The transmitter starts in monitor mode, where events are computed, signed
//! and logged but never sent; gates session revocation on a capability the
//! receiver granted; and delivers live events at least once through an
//! [`Outbox`] with retries, a dead-letter state and replay.

pub mod delivery;
pub mod error;
pub mod evidence;
#[cfg(feature = "http")]
pub mod http;
pub mod jws;
pub mod receiver;
pub mod subject;
pub mod transmitter;

pub use delivery::{DeadLetterReason, DeliveryState, Outbox, Push, PushOutcome, RetryPolicy};
pub use error::{Code, Error, Refusal};
pub use evidence::{
    EVIDENCE_REF_CLAIM, EvidenceRef, EvidenceTrust, MapResolver, Resolver, VerifiedEvidence,
    subject_descriptor, subject_digest, verify_evidence,
};
pub use jws::{Alg, SigningKey, VerifyingKey};
pub use receiver::{
    EvidencePolicy, RISK_LEVEL_CHANGE, ReceiverConfig, SESSION_REVOKED, VERIFICATION, VerifiedSet,
    verify_set,
};
pub use subject::{Principal, RiskLevel, Subject, SubjectId};
pub use transmitter::{
    Action, Capabilities, Decision, Emission, Mode, MonitorRecord, Signal, Stream, Transmitter,
};
