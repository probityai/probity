//! Compact JWS signing and verification for Security Event Tokens.
//!
//! Two algorithms: `RS256`, which the CAEP interoperability profile requires
//! with keys of at least 2048 bits, and `Ed25519` (RFC 9864). A verifying key
//! carries its algorithm, and a token whose `alg` header differs from its key's
//! algorithm is refused, so a header can never choose how it is checked.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::SystemRandom;
use ring::signature::{
    ED25519, Ed25519KeyPair, KeyPair, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_SHA256, RsaKeyPair,
    RsaPublicKeyComponents, UnparsedPublicKey,
};
use serde_json::{Map, Value, json};

use crate::error::{Code, Error, Refusal};

/// The explicit type every SSF token carries (RFC 8417 section 2.3).
pub const TYP: &str = "secevent+jwt";

/// The smallest RSA modulus accepted, in bits.
pub const MIN_RSA_BITS: usize = 2048;

/// A JWS signature algorithm this crate signs and verifies with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alg {
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    Rs256,
    /// Ed25519 (RFC 9864).
    Ed25519,
}

impl Alg {
    /// The `alg` header value this crate writes.
    pub fn name(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Ed25519 => "Ed25519",
        }
    }

    /// Whether `header` names this algorithm. An Ed25519 key also answers to
    /// the polymorphic `EdDSA` of RFC 8037, which RFC 9864 deprecates but which
    /// deployed signers still write.
    fn accepts(self, header: &str) -> bool {
        match self {
            Self::Rs256 => header == "RS256",
            Self::Ed25519 => header == "Ed25519" || header == "EdDSA",
        }
    }
}

enum SigningKind {
    Rsa(RsaKeyPair),
    Ed25519(Ed25519KeyPair),
}

/// A transmitter's signing key.
pub struct SigningKey {
    kind: SigningKind,
    kid: Option<String>,
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("alg", &self.alg())
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl SigningKey {
    /// An RS256 key from a PKCS#8 DER private key of at least 2048 bits.
    pub fn rs256_from_pkcs8(der: &[u8]) -> Result<Self, Error> {
        let pair = RsaKeyPair::from_pkcs8(der).map_err(|e| Error::Key(e.to_string()))?;
        let bits = pair.public().modulus_len() * 8;
        if bits < MIN_RSA_BITS {
            return Err(Error::Key(format!(
                "RSA modulus is {bits} bits; at least {MIN_RSA_BITS} are required"
            )));
        }
        Ok(Self {
            kind: SigningKind::Rsa(pair),
            kid: None,
        })
    }

    /// An Ed25519 key from its 32-byte seed.
    pub fn ed25519_from_seed(seed: &[u8]) -> Result<Self, Error> {
        let pair =
            Ed25519KeyPair::from_seed_unchecked(seed).map_err(|e| Error::Key(e.to_string()))?;
        Ok(Self {
            kind: SigningKind::Ed25519(pair),
            kid: None,
        })
    }

    /// Attaches the `kid` written into every header.
    #[must_use]
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    /// The key's algorithm.
    pub fn alg(&self) -> Alg {
        match self.kind {
            SigningKind::Rsa(_) => Alg::Rs256,
            SigningKind::Ed25519(_) => Alg::Ed25519,
        }
    }

    /// The verifying key for an Ed25519 signing key; RSA public keys are
    /// distributed as a JWK through the transmitter's `jwks_uri`.
    pub fn ed25519_verifying_key(&self) -> Option<VerifyingKey> {
        match &self.kind {
            SigningKind::Ed25519(pair) => {
                let public: [u8; 32] = pair.public_key().as_ref().try_into().ok()?;
                let key = VerifyingKey::ed25519(public);
                Some(match &self.kid {
                    Some(kid) => key.with_kid(kid.clone()),
                    None => key,
                })
            }
            SigningKind::Rsa(_) => None,
        }
    }

    /// Signs `payload` as a compact JWS with the SSF header.
    pub fn sign_compact(&self, payload: &[u8]) -> Result<String, Error> {
        let mut header = Map::new();
        header.insert("alg".into(), json!(self.alg().name()));
        header.insert("typ".into(), json!(TYP));
        if let Some(kid) = &self.kid {
            header.insert("kid".into(), json!(kid));
        }
        let header =
            serde_json::to_vec(&Value::Object(header)).map_err(|e| Error::Input(e.to_string()))?;
        self.sign_raw(&header, payload)
    }

    /// Signs the exact header and payload bytes given. Used to build refusal
    /// vectors whose header or payload is deliberately wrong.
    pub fn sign_raw(&self, header: &[u8], payload: &[u8]) -> Result<String, Error> {
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(payload)
        );
        let sig = match &self.kind {
            SigningKind::Rsa(pair) => {
                let mut sig = vec![0; pair.public().modulus_len()];
                pair.sign(
                    &RSA_PKCS1_SHA256,
                    &SystemRandom::new(),
                    signing_input.as_bytes(),
                    &mut sig,
                )
                .map_err(|_| Error::Signing("RSA signing failed".into()))?;
                sig
            }
            SigningKind::Ed25519(pair) => pair.sign(signing_input.as_bytes()).as_ref().to_vec(),
        };
        Ok(format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Material {
    Rsa { n: Vec<u8>, e: Vec<u8> },
    Ed25519([u8; 32]),
}

/// A transmitter's public key as a receiver trusts it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyingKey {
    material: Material,
    kid: Option<String>,
}

impl VerifyingKey {
    /// An Ed25519 verifying key from its 32 public bytes.
    pub fn ed25519(public: [u8; 32]) -> Self {
        Self {
            material: Material::Ed25519(public),
            kid: None,
        }
    }

    /// A key from a JWK: `kty` `RSA` (modulus of at least 2048 bits) or `kty`
    /// `OKP` with `crv` `Ed25519`. An `alg` member, when present, must agree.
    pub fn from_jwk(jwk: &Value) -> Result<Self, Error> {
        let field = |name: &str| -> Result<Vec<u8>, Error> {
            let text = jwk
                .get(name)
                .and_then(Value::as_str)
                .ok_or_else(|| Error::Key(format!("JWK member {name} is absent")))?;
            URL_SAFE_NO_PAD
                .decode(text)
                .map_err(|e| Error::Key(format!("JWK member {name}: {e}")))
        };
        let alg = jwk.get("alg").and_then(Value::as_str);
        let material = match jwk.get("kty").and_then(Value::as_str) {
            Some("RSA") => {
                if alg.is_some_and(|a| a != "RS256") {
                    return Err(Error::Key("RSA JWK names an alg other than RS256".into()));
                }
                let n = field("n")?;
                let e = field("e")?;
                let bits = n.iter().skip_while(|b| **b == 0).count() * 8;
                if bits < MIN_RSA_BITS {
                    return Err(Error::Key(format!(
                        "RSA modulus is {bits} bits; at least {MIN_RSA_BITS} are required"
                    )));
                }
                Material::Rsa { n, e }
            }
            Some("OKP") if jwk.get("crv").and_then(Value::as_str) == Some("Ed25519") => {
                if alg.is_some_and(|a| a != "Ed25519" && a != "EdDSA") {
                    return Err(Error::Key("Ed25519 JWK names another alg".into()));
                }
                let x: [u8; 32] = field("x")?
                    .try_into()
                    .map_err(|_| Error::Key("Ed25519 x is not 32 bytes".into()))?;
                Material::Ed25519(x)
            }
            _ => return Err(Error::Key("unsupported JWK kty or crv".into())),
        };
        Ok(Self {
            material,
            kid: jwk.get("kid").and_then(Value::as_str).map(str::to_string),
        })
    }

    /// Attaches the `kid` the key is selected by.
    #[must_use]
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    /// The key's algorithm.
    pub fn alg(&self) -> Alg {
        match self.material {
            Material::Rsa { .. } => Alg::Rs256,
            Material::Ed25519(_) => Alg::Ed25519,
        }
    }

    /// The key's `kid`, if any.
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// The key as a public JWK.
    pub fn to_jwk(&self) -> Value {
        let mut jwk = match &self.material {
            Material::Rsa { n, e } => json!({
                "kty": "RSA", "alg": "RS256", "use": "sig",
                "n": URL_SAFE_NO_PAD.encode(n), "e": URL_SAFE_NO_PAD.encode(e),
            }),
            Material::Ed25519(x) => json!({
                "kty": "OKP", "crv": "Ed25519", "alg": "Ed25519", "use": "sig",
                "x": URL_SAFE_NO_PAD.encode(x),
            }),
        };
        if let (Some(kid), Some(obj)) = (&self.kid, jwk.as_object_mut()) {
            obj.insert("kid".into(), json!(kid));
        }
        jwk
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        match &self.material {
            Material::Rsa { n, e } => RsaPublicKeyComponents { n, e }
                .verify(&RSA_PKCS1_2048_8192_SHA256, message, signature)
                .is_ok(),
            Material::Ed25519(x) => UnparsedPublicKey::new(&ED25519, x)
                .verify(message, signature)
                .is_ok(),
        }
    }
}

/// The verified contents of a compact JWS.
pub(crate) struct Verified {
    pub(crate) payload: Vec<u8>,
}

fn decode_segment(segment: &str, what: &str) -> Result<Vec<u8>, Refusal> {
    URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|e| Refusal::new(Code::SetMalformed, format!("{what} is not base64url: {e}")))
}

/// Parses a JSON object, refusing repeated members, which a parser that keeps
/// the last value would otherwise let a signer and a reader read differently.
pub(crate) fn parse_object(bytes: &[u8], what: &str) -> Result<Map<String, Value>, Refusal> {
    jcs_admit::admit(bytes).map_err(|e| {
        Refusal::new(
            Code::SetMalformed,
            format!("{what} is not admissible JSON: {e}"),
        )
    })?;
    match serde_json::from_slice::<Value>(bytes) {
        Ok(Value::Object(map)) => Ok(map),
        Ok(_) => Err(Refusal::new(
            Code::SetMalformed,
            format!("{what} is not a JSON object"),
        )),
        Err(e) => Err(Refusal::new(Code::SetMalformed, format!("{what}: {e}"))),
    }
}

/// Verifies a compact JWS SET against `keys`.
pub(crate) fn verify_compact(token: &str, keys: &[VerifyingKey]) -> Result<Verified, Refusal> {
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Refusal::new(
            Code::SetMalformed,
            "a compact JWS has exactly three segments",
        ));
    };
    let header = parse_object(&decode_segment(h, "header")?, "header")?;
    let payload = decode_segment(p, "payload")?;
    let signature = decode_segment(s, "signature")?;

    let typ = header
        .get("typ")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let typ = typ.to_ascii_lowercase();
    if typ != TYP && typ != format!("application/{TYP}") {
        return Err(Refusal::new(Code::SetTyp, format!("typ is {typ:?}")));
    }
    if header.contains_key("crit") {
        return Err(Refusal::new(
            Code::SetCrit,
            "crit names an extension this profile does not understand",
        ));
    }
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| Refusal::new(Code::SetAlg, "alg is absent"))?;
    if !["RS256", "Ed25519", "EdDSA"].contains(&alg) {
        return Err(Refusal::new(
            Code::SetAlg,
            format!("alg {alg:?} is not accepted"),
        ));
    }
    let kid = header.get("kid").and_then(Value::as_str);
    let candidates: Vec<&VerifyingKey> = keys
        .iter()
        .filter(|k| kid.is_none_or(|kid| k.kid() == Some(kid)))
        .collect();
    if candidates.is_empty() {
        return Err(Refusal::new(
            Code::SetUnknownKey,
            format!("no trusted key has kid {kid:?}"),
        ));
    }
    let matching: Vec<&&VerifyingKey> =
        candidates.iter().filter(|k| k.alg().accepts(alg)).collect();
    if matching.is_empty() {
        return Err(Refusal::new(
            Code::SetAlg,
            format!("alg {alg:?} does not match the algorithm of the selected key"),
        ));
    }
    let signing_input = &token[..h.len() + 1 + p.len()];
    if matching
        .iter()
        .any(|k| k.verify(signing_input.as_bytes(), &signature))
    {
        Ok(Verified { payload })
    } else {
        Err(Refusal::new(
            Code::SetSignature,
            "the signature does not verify under any matching trusted key",
        ))
    }
}
