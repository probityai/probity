//! Subjects: who an event is about.
//!
//! An agent's action has four parties an identity provider can act on: the
//! user it acts for, the agent itself, the tenant, and the session. SSF's
//! complex subject format (section 3.3) carries `user`, `tenant` and `session`
//! as defined members, and allows additional member names; this crate writes
//! the agent as the additional member `agent`.

use serde_json::{Map, Value, json};

use crate::error::Error;

/// One subject identifier (RFC 9493).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectId {
    /// `iss_sub`: an issuer and a subject at that issuer.
    IssSub {
        /// The issuer.
        iss: String,
        /// The subject at the issuer.
        sub: String,
    },
    /// `opaque`: an identifier only the two parties understand.
    Opaque {
        /// The identifier.
        id: String,
    },
    /// `email`.
    Email {
        /// The address.
        email: String,
    },
    /// `uri`.
    Uri {
        /// The URI.
        uri: String,
    },
}

impl SubjectId {
    /// The identifier as JSON.
    pub fn to_value(&self) -> Value {
        match self {
            Self::IssSub { iss, sub } => json!({"format": "iss_sub", "iss": iss, "sub": sub}),
            Self::Opaque { id } => json!({"format": "opaque", "id": id}),
            Self::Email { email } => json!({"format": "email", "email": email}),
            Self::Uri { uri } => json!({"format": "uri", "uri": uri}),
        }
    }
}

/// The parties an agent event is about.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Subject {
    /// The user the agent acts for.
    pub user: Option<SubjectId>,
    /// The agent.
    pub agent: Option<SubjectId>,
    /// The tenant.
    pub tenant: Option<SubjectId>,
    /// The session.
    pub session: Option<SubjectId>,
}

impl Subject {
    /// The `sub_id` claim: a complex subject with every member present.
    pub fn to_sub_id(&self) -> Result<Value, Error> {
        let mut members = Map::new();
        members.insert("format".into(), json!("complex"));
        for (name, id) in [
            ("user", &self.user),
            ("agent", &self.agent),
            ("tenant", &self.tenant),
            ("session", &self.session),
        ] {
            if let Some(id) = id {
                members.insert(name.into(), id.to_value());
            }
        }
        if members.len() == 1 {
            return Err(Error::Input("a subject names at least one party".into()));
        }
        Ok(Value::Object(members))
    }
}

/// The principal a risk level describes (CAEP 1.0 section 3.8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Principal {
    /// `USER`.
    User,
    /// `AGENT`, the additional subject member this crate writes.
    Agent,
    /// `SESSION`.
    Session,
    /// `TENANT`.
    Tenant,
}

impl Principal {
    /// The claim value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "USER",
            Self::Agent => "AGENT",
            Self::Session => "SESSION",
            Self::Tenant => "TENANT",
        }
    }
}

/// A CAEP risk level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    /// `LOW`.
    Low,
    /// `MEDIUM`.
    Medium,
    /// `HIGH`.
    High,
}

impl RiskLevel {
    /// The claim value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
        }
    }
}
