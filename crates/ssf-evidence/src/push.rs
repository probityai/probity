//! The receiving end of RFC 8935 push delivery, independent of any HTTP
//! server: given a request's `Content-Type`, `Authorization` and body, decide
//! the status, headers and body to answer with.

use serde_json::json;

use crate::error::{Code, Refusal};
use crate::evidence::Resolver;
use crate::receiver::{JtiLedger, ReceiverConfig, VerifiedSet, verify_set};

/// The media type of a pushed token (RFC 8417 section 7.2).
pub const SECEVENT_MEDIA_TYPE: &str = "application/secevent+jwt";

/// The language of every error description this crate writes.
pub const DESCRIPTION_LANGUAGE: &str = "en";

/// What a push receiver answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushResponse {
    /// HTTP 202: the token verified and is recorded. Act on it.
    Accepted(Box<VerifiedSet>),
    /// HTTP 202: this token, byte for byte, was accepted before. RFC 8935
    /// section 2 requires the same answer as the first delivery got; the
    /// receiver does not act on it again. The refusal says which `jti`.
    AlreadyReceived(Refusal),
    /// HTTP 400 with the RFC 8935 section 2.3 error object.
    Refused(Refusal),
    /// HTTP 503: the receiver could not finish validating the token (the
    /// evidence did not resolve, the replay ledger failed). The transmitter
    /// retries, and nothing was recorded.
    Unavailable(Refusal),
}

impl PushResponse {
    /// The HTTP status code.
    pub fn status(&self) -> u16 {
        match self {
            Self::Accepted(_) | Self::AlreadyReceived(_) => 202,
            Self::Refused(_) => 400,
            Self::Unavailable(_) => 503,
        }
    }

    /// The response header fields this crate decides: `Content-Type` and
    /// `Content-Language` for a 400 (RFC 8935 section 2.3), none otherwise.
    pub fn headers(&self) -> Vec<(&'static str, &'static str)> {
        match self {
            Self::Refused(_) => vec![
                ("Content-Type", "application/json"),
                ("Content-Language", DESCRIPTION_LANGUAGE),
            ],
            _ => Vec::new(),
        }
    }

    /// The response body: the `{"err", "description"}` object for a 400, and
    /// empty otherwise (RFC 8935 section 2.2 requires an empty 202 body).
    pub fn body(&self) -> String {
        match self {
            Self::Refused(refusal) => json!({
                "err": refusal.code.set_error_code(),
                "description": refusal.to_string(),
            })
            .to_string(),
            _ => String::new(),
        }
    }
}

/// A push endpoint: what it trusts, where it fetches evidence, where it
/// records accepted tokens, and the credential a transmitter must present.
#[derive(Clone, Copy)]
pub struct PushReceiver<'a> {
    /// The transmitter, audience and keys.
    pub config: &'a ReceiverConfig,
    /// Where evidence envelopes are fetched.
    pub resolver: &'a dyn Resolver,
    /// Where accepted tokens are recorded.
    pub ledger: &'a dyn JtiLedger,
    /// The exact `Authorization` value the transmitter must send, compared in
    /// constant time; `None` when the deployment authenticates the
    /// transmitter before the request reaches here (mutual TLS, a gateway).
    pub authorization: Option<&'a str>,
}

impl std::fmt::Debug for PushReceiver<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushReceiver")
            .field("issuer", &self.config.issuer)
            .field("audience", &self.config.audience)
            .field("authorization", &self.authorization.map(|_| "<set>"))
            .finish_non_exhaustive()
    }
}

impl PushReceiver<'_> {
    /// Answers one push request. The transmitter is authenticated first, then
    /// the media type is checked, then the body is verified as a token.
    pub fn receive(
        &self,
        content_type: Option<&str>,
        authorization: Option<&str>,
        body: &[u8],
    ) -> PushResponse {
        match self.check(content_type, authorization, body) {
            Ok(set) => PushResponse::Accepted(Box::new(set)),
            Err(r) if r.code == Code::SetJtiReplayed => PushResponse::AlreadyReceived(r),
            Err(r) if r.code.is_transient() => PushResponse::Unavailable(r),
            Err(r) => PushResponse::Refused(r),
        }
    }

    fn check(
        &self,
        content_type: Option<&str>,
        authorization: Option<&str>,
        body: &[u8],
    ) -> Result<VerifiedSet, Refusal> {
        if let Some(expected) = self.authorization {
            let given = authorization.unwrap_or_default();
            if !same_bytes(expected.as_bytes(), given.as_bytes()) {
                return Err(Refusal::new(
                    Code::PushAuthentication,
                    "the Authorization header does not carry the transmitter's credential",
                ));
            }
        }
        check_content_type(content_type)?;
        let token = std::str::from_utf8(body)
            .map_err(|_| Refusal::new(Code::SetMalformed, "the body is not UTF-8"))?;
        verify_set(token, self.config, self.resolver, self.ledger)
    }
}

/// RFC 8935 section 2.1: the request's `Content-Type` MUST be
/// `application/secevent+jwt`. The type and subtype compare without regard to
/// case and parameters are ignored, as media types do (RFC 9110 section 8.3.1).
fn check_content_type(content_type: Option<&str>) -> Result<(), Refusal> {
    let matches = content_type
        .and_then(|v| v.split(';').next())
        .is_some_and(|t| t.trim().eq_ignore_ascii_case(SECEVENT_MEDIA_TYPE));
    if matches {
        Ok(())
    } else {
        Err(Refusal::new(
            Code::PushContentType,
            format!("Content-Type is {content_type:?}, not {SECEVENT_MEDIA_TYPE}"),
        ))
    }
}

/// Equality whose time depends only on the lengths.
fn same_bytes(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
