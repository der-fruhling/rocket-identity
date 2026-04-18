use std::fmt::{Display, Formatter};
use std::ops::{Add, Deref};
use rocket::serde::{Deserialize, Serialize};
use chrono::{DateTime, TimeDelta, TimeZone, Utc};
use url::Url;
use crate::Combine;
use crate::keys::JwkContent;

/// Identifies an algorithm used for signing JWTs.
#[derive(Serialize, Deserialize, Eq, Ord, PartialOrd, PartialEq, Debug, Clone, Copy, Default)]
pub enum JwtAlgorithm {
    /// > HMAC using SHA-256
    HS256,
    /// > HMAC using SHA-384
    HS384,
    /// > HMAC using SHA-512
    HS512,
    /// > RSASSA-PKCS1-v1_5 using SHA-256
    RS256,
    /// > RSASSA-PKCS1-v1_5 using SHA-384
    RS384,
    /// > RSASSA-PKCS1-v1_5 using SHA-512
    RS512,
    /// > ECDSA using P-256 using SHA-256
    ES256,
    /// > ECDSA using P-384 using SHA-384
    ES384,
    /// > ECDSA using P-521 _(sic?)_ using SHA-512
    ES512,
    /// > RSASSA-PSS using SHA-256 and MGF1 with SHA-256
    PS256,
    /// > RSASSA-PSS using SHA-384 and MGF1 with SHA-384
    PS384,
    /// > RSASSA-PSS using SHA-512 and MGF1 with SHA-512
    PS512,

    /// > No digital signature or MAC performed
    #[serde(rename = "none")]
    None,

    #[serde(other)]
    #[default]
    Unknown,
}

#[derive(Serialize, Deserialize, Eq, Ord, PartialOrd, PartialEq, Debug, Clone, Copy, Default)]
pub enum JwtType {
    #[default]
    JWT,

    #[serde(other)]
    Unknown,
}

/// Known claims within the header of a JWT.
///
/// <https://datatracker.ietf.org/doc/html/rfc7515#section-4.1>
///
/// If passed, the [Extra] type parameter must implement [Combine],
/// [Serialize], [Deserialize], and should be [Send] + [Sync].
#[derive(Serialize, Deserialize, Eq, Ord, PartialOrd, PartialEq, Debug, Clone, Default)]
pub struct JwtHeader<Extra = ()> {
    pub alg: JwtAlgorithm,
    pub typ: JwtType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jku: Option<Url>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwk: Option<JwkContent>,
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
    #[serde(flatten)]
    pub extra: Extra
}

impl<'a, Extra: Combine> Add<JwtHeader<Extra>> for &'a JwtHeader<Extra> {
    type Output = JwtHeader<Extra>;

    fn add(self, rhs: JwtHeader<Extra>) -> Self::Output {
        JwtHeader {
            alg: self.alg,
            typ: self.typ,
            jku: rhs.jku.or_else(|| self.jku.clone()),
            jwk: rhs.jwk.or_else(|| self.jwk.clone()),
            kid: rhs.kid.or_else(|| self.kid.clone()),
            x5u: rhs.x5u.or_else(|| self.x5u.clone()),
            x5c: rhs.x5c.or_else(|| self.x5c.clone()),
            x5t: rhs.x5t.or_else(|| self.x5t.clone()),
            x5t_s256: rhs.x5t_s256.or_else(|| self.x5t_s256.clone()),
            extra: self.extra.with(rhs.extra),
        }
    }
}

/// A JWT claim that may be a URL / URI.
///
/// This crate only supports parsing URLs, so URIs may only be available as the
/// [Self::String] variant.
#[derive(Serialize, Deserialize, Eq, Ord, PartialOrd, PartialEq, Debug, Clone)]
#[serde(untagged)]
pub enum JwtUriClaim {
    Url(Url),
    String(String),
}

impl Deref for JwtUriClaim {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        match self {
            JwtUriClaim::Url(u) => u.as_str(),
            JwtUriClaim::String(s) => s.as_str(),
        }
    }
}

impl Display for JwtUriClaim {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            JwtUriClaim::Url(u) => Display::fmt(u, f),
            JwtUriClaim::String(s) => f.write_str(s),
        }
    }
}

impl From<&str> for JwtUriClaim {
    fn from(value: &str) -> Self {
        if let Ok(u) = Url::parse(value) {
            Self::Url(u)
        } else {
            Self::String(value.to_string())
        }
    }
}

impl From<String> for JwtUriClaim {
    fn from(value: String) -> Self {
        if let Ok(u) = Url::parse(&value) {
            Self::Url(u)
        } else {
            Self::String(value)
        }
    }
}

impl From<Url> for JwtUriClaim {
    fn from(value: Url) -> Self {
        Self::Url(value)
    }
}

/// An extendable collection of JWT claims.
///
/// This struct includes the [defined claims] and allows you to add your own
/// to represent more application-specific state (like scopes). Create via
/// [JwtClaims::new] and [JwtClaimsBuilder]'s methods.
///
/// [defined claims]: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1
///
/// ```
/// # use url::Url;
/// # use rocket_identity::{JwtClaims, JwtUriClaim};
/// let claims = JwtClaims::new()
///     .issuer("https://example.com/issuer")
///     .subject("client")
///     .build();
///
/// assert_eq!(claims.issuer, Some(Url::parse("https://example.com/issuer").unwrap().into()));
/// assert_eq!(claims.subject, Some("client".into()))
/// ```
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct JwtClaims<Extra = ()> {
    /// Represents the issuer of the token.
    #[serde(skip_serializing_if = "Option::is_none", default, rename = "iss")]
    #[doc(alias = "iss")]
    pub issuer: Option<JwtUriClaim>,

    /// Represents the resource represented by the token.
    ///
    /// In the context of client credentials (e.g. an app acting as itself),
    /// this field will likely be an identifier representing the client.
    /// If the token represents a user's authorization to access some resource,
    /// this field likely is an identifier of the user.
    ///
    /// If `issuer` is not provided, this field **must** be globally unique
    /// as for the subject's representation. Otherwise, this field is unique
    /// within the context of the issuer.
    #[serde(skip_serializing_if = "Option::is_none", default, rename = "sub")]
    #[doc(alias = "sub")]
    pub subject: Option<JwtUriClaim>,

    /// Represents the intended audiences of the token.
    ///
    /// Each "processor" of the token **must** be identified in this field.
    /// Otherwise, the token **must** be rejected as per the spec.
    #[serde(skip_serializing_if = "Vec::is_empty", default, rename = "aud")]
    #[doc(alias = "aud")]
    pub audience: Vec<JwtUriClaim>,

    /// The expiration time of the token.
    #[serde(
        with = "crate::datetime_serializer",
        skip_serializing_if = "Option::is_none",
        default,
        rename = "exp"
    )]
    #[doc(alias = "exp")]
    pub expires: Option<DateTime<Utc>>,

    /// A time before which this token **must** be rejected.
    #[serde(
        with = "crate::datetime_serializer",
        skip_serializing_if = "Option::is_none",
        default,
        rename = "nbf"
    )]
    #[doc(alias = "nbf")]
    pub not_before: Option<DateTime<Utc>>,

    /// The time this token was issued at.
    ///
    /// While the spec does not require it, this crate will treat this field
    /// as a "backup" `not_before` if that field is not provided. Eg., the
    /// token will be rejected if `not_before` is [None], this field is
    /// [Some], and this field is later than the current time.
    #[serde(
        with = "crate::datetime_serializer",
        skip_serializing_if = "Option::is_none",
        default,
        rename = "iat"
    )]
    #[doc(alias = "iat")]
    pub issued_at: Option<DateTime<Utc>>,

    /// A globally unique identifier for this token.
    ///
    /// This may be used to allow token revokation and in preventing certain
    /// attacks.
    #[serde(skip_serializing_if = "Option::is_none", default, rename = "jti")]
    #[doc(alias = "jti")]
    pub jwt_id: Option<String>,

    #[serde(flatten)]
    extra: Extra,
}

/// A builder created by [JwtClaims::new].
pub struct JwtClaimsBuilder<Extra = ()>(JwtClaims<Extra>);

impl JwtClaims<()> {
    /// Creates a new [JwtClaimsBuilder] that can be used to construct a new
    /// claim set.
    pub fn new() -> JwtClaimsBuilder {
        JwtClaimsBuilder(Self::default())
    }

    /// Takes ownership of `self` and moves all fields into a new claim set,
    /// then sets the `extra` field to the provided value.
    ///
    /// This method can be used to extend the claim set with additional fields.
    ///
    /// [Extra] should implement [Serialize] and [Deserialize]
    pub fn with<Extra>(self, extra: Extra) -> JwtClaims<Extra> {
        JwtClaims {
            issuer: self.issuer,
            subject: self.subject,
            audience: self.audience,
            expires: self.expires,
            not_before: self.not_before,
            issued_at: self.issued_at,
            jwt_id: self.jwt_id,
            extra,
        }
    }
}

impl<Extra> JwtClaims<Extra> {
    /// Splits this claim set into a "simple" claim set (one without any extra
    /// fields) and the `extra` value contained within `self`.
    pub fn split(self) -> (JwtClaims<()>, Extra) {
        (
            JwtClaims {
                issuer: self.issuer,
                subject: self.subject,
                audience: self.audience,
                expires: self.expires,
                not_before: self.not_before,
                issued_at: self.issued_at,
                jwt_id: self.jwt_id,
                extra: (),
            },
            self.extra,
        )
    }
}

macro_rules! builder {
    {
        $($(#[$meta:meta])* $name:ident$(<$($param:ident: $bound:path),*>)?($type:ty$(, $conv:ident$(($($args:expr),* $(,)?))?)*) -> $field:ident),* $(,)?
    } => {$(
        $(#[$meta])*
        pub fn $name$(<$($param: $bound)*>)?(self, $field: $type) -> Self {
            Self(JwtClaims::<_> {
                $field: $field$(.$conv($($($args),*)?))*,
                ..self.0
            })
        }
    )*};
}

impl<Extra> JwtClaimsBuilder<Extra> {
    builder! {
        /// See [JwtClaims::issuer].
        #[doc(alias = "iss")] issuer(impl Into<JwtUriClaim>, into, into) -> issuer,

        /// See [JwtClaims::subject].
        #[doc(alias = "sub")] subject(impl Into<JwtUriClaim>, into, into) -> subject,

        /// See [JwtClaims::audience] and [Self::audience] for a single value.
        #[doc(alias = "aud")] audiences<T: Into<JwtUriClaim>>(impl IntoIterator<Item = T>, into_iter, map(|v| v.into()), collect) -> audience,

        /// See [JwtClaims::expires] and [Self::expires_in].
        #[doc(alias = "exp")] expires<Tz: TimeZone>(DateTime<Tz>, to_utc, into) -> expires,

        /// See [JwtClaims::not_before] and [Self::not_until].
        #[doc(alias = "nbf")] not_before<Tz: TimeZone>(DateTime<Tz>, to_utc, into) -> not_before,

        /// See [JwtClaims::issued_at] and [Self::issued_now].
        #[doc(alias = "iat")] issued_at<Tz: TimeZone>(DateTime<Tz>, to_utc, into) -> issued_at,

        /// See [JwtClaims::jwt_id].
        #[doc(alias = "jti")] jwt_id(impl Into<String>, into, into) -> jwt_id,
    }

    /// Appends a single audience value to this token, preserving existing values.
    ///
    /// ```
    /// # use rocket_identity::JwtClaims;
    /// let a = JwtClaims::new()
    ///     .audiences(["test1", "test2"])
    ///     .build();
    ///
    /// let b = JwtClaims::new()
    ///     .audience("test1")
    ///     .audience("test2")
    ///     .build();
    ///
    /// assert_eq!(a, b);
    /// ```
    pub fn audience(mut self, audience: impl Into<JwtUriClaim>) -> Self {
        self.0.audience.push(audience.into());
        self
    }

    /// Equivalent to `self.issued_at(Utc::now())`.
    pub fn issued_now(self) -> Self {
        self.issued_at(Utc::now())
    }

    /// Sets [Self::expires] with a [TimeDelta] relative to the current
    /// [Self::issued_at] value.
    ///
    /// Call [Self::issued_at] or [Self::issued_now] before this method.
    ///
    /// ```
    /// # use chrono::{TimeDelta, Utc};
    /// # use rocket_identity::JwtClaims;
    /// let iss = Utc::now();
    /// let a = JwtClaims::new()
    ///     .issued_at(iss)
    ///     .expires_in(TimeDelta::seconds(60))
    ///     .build();
    ///
    /// let b = JwtClaims::new()
    ///     .issued_at(iss)
    ///     .expires(iss + TimeDelta::seconds(60))
    ///     .build();
    ///
    /// assert_eq!(a, b);
    /// ```
    pub fn expires_in(self, time_delta: TimeDelta) -> Self {
        let expiration = self.0.issued_at.unwrap_or_else(Utc::now) + time_delta;
        self.expires(expiration)
    }

    /// Sets [Self::not_before] with a [TimeDelta] relative to the current
    /// [Self::issued_at] value.
    ///
    /// Call [Self::issued_at] or [Self::issued_now] before this method.
    ///
    /// ```
    /// # use chrono::{TimeDelta, Utc};
    /// # use rocket_identity::JwtClaims;
    /// let iss = Utc::now();
    /// let a = JwtClaims::new()
    ///     .issued_at(iss)
    ///     .not_until(TimeDelta::seconds(60))
    ///     .build();
    ///
    /// let b = JwtClaims::new()
    ///     .issued_at(iss)
    ///     .not_before(iss + TimeDelta::seconds(60))
    ///     .build();
    ///
    /// assert_eq!(a, b);
    /// ```
    pub fn not_until(self, time_delta: TimeDelta) -> Self {
        let not_before = self.0.issued_at.unwrap_or_else(Utc::now) + time_delta;
        self.not_before(not_before)
    }

    /// Finalizes this claim set.
    pub fn build(self) -> JwtClaims<Extra> {
        self.0
    }
}

impl JwtClaimsBuilder<()> {
    /// Recreates this builder with the provided `extra` value.
    ///
    /// Similar to [JwtClaims::with] but for the builder type. Unlike that
    /// method, this one is only implemented for "simple" claim sets that
    /// have no `extra` data already.
    pub fn with<Extra>(self, extra: Extra) -> JwtClaimsBuilder<Extra> {
        JwtClaimsBuilder(JwtClaims {
            issuer: self.0.issuer,
            subject: self.0.subject,
            audience: self.0.audience,
            expires: self.0.expires,
            not_before: self.0.not_before,
            issued_at: self.0.issued_at,
            jwt_id: self.0.jwt_id,
            extra,
        })
    }
}