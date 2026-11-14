//! Push delivery over HTTP (RFC 8935) and evidence retrieval over HTTP.

use std::time::Duration;

use serde_json::Value;

use crate::delivery::{Push, PushOutcome};
use crate::evidence::{MAX_ENVELOPE_BYTES, Resolver};

const MAX_ERROR_BODY: u64 = 64 * 1024;

fn agent(timeout: Duration) -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(timeout))
        .build()
        .into()
}

/// Pushes tokens to a receiver's push endpoint.
#[derive(Debug, Clone)]
pub struct HttpPush {
    endpoint: String,
    authorization: Option<String>,
    agent: ureq::Agent,
}

impl HttpPush {
    /// A pusher to `endpoint`, with a per-request timeout.
    pub fn new(endpoint: impl Into<String>, timeout: Duration) -> Self {
        Self {
            endpoint: endpoint.into(),
            authorization: None,
            agent: agent(timeout),
        }
    }

    /// Sends this `Authorization` header value with every push.
    #[must_use]
    pub fn with_authorization(mut self, value: impl Into<String>) -> Self {
        self.authorization = Some(value.into());
        self
    }
}

impl Push for HttpPush {
    fn push(&self, token: &str) -> PushOutcome {
        let mut request = self
            .agent
            .post(&self.endpoint)
            .header("Content-Type", "application/secevent+jwt")
            .header("Accept", "application/json");
        if let Some(auth) = &self.authorization {
            request = request.header("Authorization", auth);
        }
        let mut response = match request.send(token) {
            Ok(response) => response,
            Err(e) => {
                return PushOutcome::Transient {
                    status: None,
                    detail: e.to_string(),
                };
            }
        };
        let status = response.status().as_u16();
        if status == 202 {
            return PushOutcome::Accepted;
        }
        let body = response
            .body_mut()
            .with_config()
            .limit(MAX_ERROR_BODY)
            .read_to_string()
            .unwrap_or_default();
        if status == 400 {
            let parsed: Option<Value> = serde_json::from_str(&body).ok();
            let field = |name: &str| {
                parsed
                    .as_ref()
                    .and_then(|v| v.get(name))
                    .and_then(Value::as_str)
                    .map(str::to_string)
            };
            return PushOutcome::Rejected {
                err: field("err").unwrap_or_else(|| "invalid_request".into()),
                description: field("description").unwrap_or(body),
            };
        }
        PushOutcome::Transient {
            status: Some(status),
            detail: body,
        }
    }
}

/// Retrieves evidence envelopes over HTTPS.
#[derive(Debug, Clone)]
pub struct HttpResolver {
    agent: ureq::Agent,
    allow_plain_http: bool,
}

impl HttpResolver {
    /// A resolver that accepts only `https` URIs.
    pub fn new(timeout: Duration) -> Self {
        Self {
            agent: agent(timeout),
            allow_plain_http: false,
        }
    }

    /// Also accepts `http` URIs, for a receiver on a closed network or a test.
    #[must_use]
    pub fn allowing_plain_http(mut self) -> Self {
        self.allow_plain_http = true;
        self
    }
}

impl Resolver for HttpResolver {
    fn fetch(&self, uri: &str) -> Result<Vec<u8>, String> {
        let scheme_ok =
            uri.starts_with("https://") || (self.allow_plain_http && uri.starts_with("http://"));
        if !scheme_ok {
            return Err(format!("{uri} is not an https URI"));
        }
        let mut response = self.agent.get(uri).call().map_err(|e| e.to_string())?;
        if response.status().as_u16() != 200 {
            return Err(format!(
                "{uri} answered HTTP {}",
                response.status().as_u16()
            ));
        }
        // One byte over the cap is read so an oversized envelope is refused
        // by the caller's size check, never silently truncated.
        response
            .body_mut()
            .with_config()
            .limit(MAX_ENVELOPE_BYTES as u64 + 1)
            .read_to_vec()
            .map_err(|e| e.to_string())
    }
}
