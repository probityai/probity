//! The receiving end of RFC 8936 poll delivery: the request and response
//! documents, parsed strictly, and one poll that verifies every token returned
//! and builds the acknowledgements for the next poll.
//!
//! Parsing is strict in three ways: a repeated member, a member of the wrong
//! type and a member RFC 8936 does not define are each refused. An unknown
//! member is refused rather than skipped because the likely unknown member is
//! a misspelt known one, and skipping `moreavailable` or `seterrs` would make
//! a receiver stop polling early or a transmitter miss an error report.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Code, Refusal};
use crate::evidence::Resolver;
use crate::receiver::{JtiLedger, ReceiverConfig, VerifiedSet, verify_delivered};

/// An entry of `setErrs`: why the recipient refused one token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetErr {
    /// A Security Event Token Error Code (RFC 8935 section 2.4).
    pub err: String,
    /// A human-readable description.
    pub description: String,
}

/// The poll request document (RFC 8936 section 2.2).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PollRequest {
    /// The `jti` of each token received and acknowledged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ack: Vec<String>,
    /// The `jti` of each token refused, with the reason.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub set_errs: BTreeMap<String, SetErr>,
    /// The most tokens to return; `0` acknowledges only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_events: Option<u64>,
    /// Answer at once even with nothing to return (short polling).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub return_immediately: Option<bool>,
}

impl PollRequest {
    /// Parses a poll request strictly.
    pub fn from_json(bytes: &[u8]) -> Result<Self, Refusal> {
        parse_strict(bytes, Code::PollRequest, "poll request")
    }

    /// The request as JSON.
    pub fn to_json(&self) -> Result<String, Refusal> {
        serde_json::to_string(self).map_err(|e| Refusal::new(Code::PollRequest, e.to_string()))
    }
}

/// The poll response document (RFC 8936 section 2.3).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PollResponse {
    /// Each token returned, keyed by its `jti`. Required: a response with
    /// nothing to deliver carries an empty object.
    pub sets: BTreeMap<String, String>,
    /// Whether more tokens are waiting; absent means `false`.
    #[serde(default)]
    pub more_available: bool,
}

impl PollResponse {
    /// Parses a poll response strictly.
    pub fn from_json(bytes: &[u8]) -> Result<Self, Refusal> {
        parse_strict(bytes, Code::PollResponse, "poll response")
    }
}

fn parse_strict<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    code: Code,
    what: &str,
) -> Result<T, Refusal> {
    jcs_admit::admit(bytes)
        .map_err(|e| Refusal::new(code, format!("{what} is not admissible JSON: {e}")))?;
    serde_json::from_slice(bytes).map_err(|e| Refusal::new(code, format!("{what}: {e}")))
}

/// Sends one poll request to a transmitter.
pub trait PollTransport {
    /// Sends `request` and returns the body of the transmitter's HTTP 200
    /// answer; any other outcome is an `Err` describing it.
    fn poll(&self, request: &PollRequest) -> Result<Vec<u8>, String>;
}

/// What one poll returned, and what the next poll must say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PollOutcome {
    /// Tokens verified and recorded by this poll, in `jti` order. Act on each.
    pub verified: Vec<VerifiedSet>,
    /// Tokens accepted by an earlier poll and delivered again. They are
    /// acknowledged again (RFC 8936 section 2.4) and not acted on.
    pub already_received: Vec<String>,
    /// Tokens refused for a reason that says nothing about the token (the
    /// evidence did not resolve, the ledger failed). Neither acknowledged nor
    /// reported, so the transmitter delivers them again.
    pub deferred: BTreeMap<String, Refusal>,
    /// The next request: `ack` names every verified and already-received
    /// token, `setErrs` every refused one, and `maxEvents` and
    /// `returnImmediately` are carried over from this poll's request.
    pub next: PollRequest,
    /// The response's `moreAvailable`.
    pub more_available: bool,
}

/// One RFC 8936 poll: send `request`, parse the response strictly, and verify
/// each token under its member name. A transport failure or a malformed
/// response is an `Err` and changes nothing; the same request can be sent
/// again.
pub fn poll_once(
    transport: &dyn PollTransport,
    request: &PollRequest,
    config: &ReceiverConfig,
    resolver: &dyn Resolver,
    ledger: &dyn JtiLedger,
) -> Result<PollOutcome, Refusal> {
    let body = transport
        .poll(request)
        .map_err(|e| Refusal::new(Code::PollTransport, e))?;
    let response = PollResponse::from_json(&body)?;
    let mut outcome = PollOutcome {
        verified: Vec::new(),
        already_received: Vec::new(),
        deferred: BTreeMap::new(),
        next: PollRequest {
            max_events: request.max_events,
            return_immediately: request.return_immediately,
            ..PollRequest::default()
        },
        more_available: response.more_available,
    };
    for (jti, token) in &response.sets {
        match verify_delivered(token, Some(jti), config, resolver, ledger) {
            Ok(set) => {
                outcome.next.ack.push(jti.clone());
                outcome.verified.push(set);
            }
            Err(r) if r.code == Code::SetJtiReplayed => {
                outcome.next.ack.push(jti.clone());
                outcome.already_received.push(jti.clone());
            }
            Err(r) if r.code.is_transient() => {
                outcome.deferred.insert(jti.clone(), r);
            }
            Err(r) => {
                outcome.next.set_errs.insert(
                    jti.clone(),
                    SetErr {
                        err: r.code.set_error_code().to_string(),
                        description: r.to_string(),
                    },
                );
            }
        }
    }
    Ok(outcome)
}
