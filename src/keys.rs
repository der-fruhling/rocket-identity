use rocket::serde::{Deserialize, Serialize};
use url::Url;
use crate::JwtAlgorithm;

#[derive(Serialize, Deserialize, Eq, Ord, PartialOrd, PartialEq, Debug, Clone)]
pub enum JwkEllipticCurve {
    #[serde(rename = "P-256")]
    P256,
    #[serde(rename = "P-384")]
    P384,
    #[serde(rename = "P-521")]
    P521,
}

#[derive(Serialize, Deserialize, Eq, Ord, PartialOrd, PartialEq, Debug, Clone)]
pub struct JwkRSAOtherPrime {
    pub r: String,
    pub d: String,
    pub t: String,
}

#[derive(Serialize, Deserialize, Eq, Ord, PartialOrd, PartialEq, Debug, Clone)]
pub struct JwkRSAPrivateKey {
    pub d: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub q: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dq: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qi: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub oth: Vec<JwkRSAOtherPrime>,
}

#[derive(Serialize, Deserialize, Eq, Ord, PartialOrd, PartialEq, Debug, Clone)]
#[serde(tag = "kty")]
pub enum JwkKey {
    EC {
        crv: JwkEllipticCurve,
        x: String,
        y: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        d: Option<String>,
    },

    RSA {
        n: String,
        e: String,
        #[serde(default, flatten, skip_serializing_if = "Option::is_none")]
        private_key: Option<JwkRSAPrivateKey>,
    },

    #[serde(rename = "oct")]
    Oct { k: String },
}

#[derive(Serialize, Deserialize, Eq, Ord, PartialOrd, PartialEq, Debug, Clone, Default)]
#[serde(rename_all = "lowercase")]
pub enum JwkUse {
    #[default]
    Sig,
    Enc,
}

#[derive(Serialize, Deserialize, Eq, Ord, PartialOrd, PartialEq, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub enum JwkKeyOp {
    Sign,
    Verify,
    Encrypt,
    Decrypt,
    WrapKey,
    UnwrapKey,
    DeriveKey,
    DeriveBits,
}

/// Represents the contents of a [JSON Web Key].
///
/// These structures can be used to share public (and private) keys to allow
/// third-party clients to verify tokens. This is notably used in OpenID
/// Connect to avoid needing to call the issuer to validate ID tokens.
///
/// [JSON Web Key]: https://datatracker.ietf.org/doc/html/rfc7517
#[derive(Serialize, Deserialize, Eq, Ord, PartialOrd, PartialEq, Debug, Clone)]
pub struct JwkContent {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<JwtAlgorithm>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x5u: Option<Url>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,
    #[serde(rename = "x5t#S256", default, skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<String>,
    #[serde(default, rename = "use")]
    pub r#use: JwkUse,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_ops: Vec<JwkKeyOp>,
    #[serde(flatten)]
    pub key: JwkKey,
}

/// A sequence of [JwkContent] that conforms to the `/.well-known/jwks.json`
/// format.
#[derive(Serialize, Deserialize, Eq, Ord, PartialOrd, PartialEq, Debug, Clone)]
pub struct JwkSet {
    pub keys: Vec<JwkContent>,
}