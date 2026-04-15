use crate::secret::SecretStr;
use crate::tokens::{SignToken, TokenSignError, TokenSignResult, TokenVerifyError, VerifyToken};
use base64ct::{Base64UrlUnpadded, Decoder};
use chrono::{DateTime, TimeZone, Utc};
use rocket::fairing::{Info, Kind};
use rocket::http::uri::Origin;
use rocket::http::{Method, Status};
use rocket::request::{FromRequest, Outcome};
use rocket::response::Responder;
use rocket::{async_trait, Build, Request, Rocket, Route};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::borrow::{Borrow, Cow};
use std::collections::{BTreeSet, HashSet};
use std::fmt::{Debug, Display, Formatter, Write};
use std::hash::Hash;
use std::marker::PhantomData;
use std::ops::Deref;
use std::sync::Arc;
use thiserror::Error;
use url::Url;

pub mod oauth2;
pub mod secret;
pub mod tokens;
pub mod oidc;

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
    Unknown
}

#[derive(Serialize, Deserialize, Eq, Ord, PartialOrd, PartialEq, Debug, Clone, Copy, Default)]
pub enum JwtType {
    #[default]
    JWT,

    #[serde(other)]
    Unknown
}

#[derive(Serialize, Deserialize, Eq, Ord, PartialOrd, PartialEq, Debug, Clone)]
pub enum JwkEllipticCurve {
    #[serde(rename = "P-256")]
    P256,
    #[serde(rename = "P-384")]
    P384,
    #[serde(rename = "P-521")]
    P521
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
    pub oth: Vec<JwkRSAOtherPrime>
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
    Oct {
        k: String,
    }
}

#[derive(Serialize, Deserialize, Eq, Ord, PartialOrd, PartialEq, Debug, Clone, Default)]
#[serde(rename_all = "lowercase")]
pub enum JwkUse {
    #[default] Sig,
    Enc
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

#[derive(Serialize, Deserialize, Eq, Ord, PartialOrd, PartialEq, Debug, Clone)]
pub struct JwkSet {
    pub keys: Vec<JwkContent>,
}

#[derive(Serialize, Deserialize, Eq, Ord, PartialOrd, PartialEq, Debug, Clone, Default)]
pub struct JwtHeader {
    pub alg: JwtAlgorithm,
    pub typ: JwtType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jku: Option<Url>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwk: Option<String>,
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
}

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

pub mod datetime_serializer {
    use chrono::{DateTime, Utc};
    use serde::de::Error;
    use serde::{Deserializer, Serializer};
    use std::fmt::Formatter;

    pub fn serialize<S: Serializer>(date_time: &Option<DateTime<Utc>>, s: S) -> Result<S::Ok, S::Error> {
        match date_time {
            None => s.serialize_none(),
            Some(v) => s.serialize_i64(v.timestamp())
        }
    }

    struct Visitor;

    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = Option<DateTime<Utc>>;

        fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
            formatter.write_str("a unix timestamp")
        }

        fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
        where
            E: Error
        {
            DateTime::from_timestamp_secs(v).map(Some).ok_or_else(|| E::custom("invalid timestamp"))
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
        where
            E: Error,
        {
            if v < i64::MAX as u64 {
                self.visit_i64(v as i64)
            } else {
                Err(E::custom("integer too large"))
            }
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: Error,
        {
            Ok(None)
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_i64(self)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<DateTime<Utc>>, D::Error> {
        d.deserialize_option(Visitor)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct JwtClaims<Extra = ()> {
    #[serde(skip_serializing_if = "Option::is_none", default, rename = "iss")]
    #[doc(alias = "iss")]
    pub issuer: Option<JwtUriClaim>,

    #[serde(skip_serializing_if = "Option::is_none", default, rename = "sub")]
    #[doc(alias = "sub")]
    pub subject: Option<JwtUriClaim>,

    #[serde(skip_serializing_if = "Option::is_none", default, rename = "aud")]
    #[doc(alias = "aud")]
    pub audience: Option<JwtUriClaim>,

    #[serde(with = "datetime_serializer", skip_serializing_if = "Option::is_none", default, rename = "exp")]
    #[doc(alias = "exp")]
    pub expires: Option<DateTime<Utc>>,

    #[serde(with = "datetime_serializer", skip_serializing_if = "Option::is_none", default, rename = "nbf")]
    #[doc(alias = "nbf")]
    pub not_before: Option<DateTime<Utc>>,

    #[serde(with = "datetime_serializer", skip_serializing_if = "Option::is_none", default, rename = "iat")]
    #[doc(alias = "iat")]
    pub issued_at: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none", default, rename = "jti")]
    #[doc(alias = "jti")]
    pub jwt_id: Option<String>,

    #[serde(flatten)]
    extra: Extra
}

pub struct JwtClaimsBuilder<Extra = ()>(JwtClaims<Extra>);

impl JwtClaims<()> {
    pub fn new() -> JwtClaimsBuilder {
        JwtClaimsBuilder(Self::default())
    }

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
    pub fn split(self) -> (JwtClaims<()>, Extra) {
        (JwtClaims {
            issuer: self.issuer,
            subject: self.subject,
            audience: self.audience,
            expires: self.expires,
            not_before: self.not_before,
            issued_at: self.issued_at,
            jwt_id: self.jwt_id,
            extra: (),
        }, self.extra)
    }
}

macro_rules! builder {
    {
        $($(#[$meta:meta])* $name:ident$(<$($param:ident: $bound:path),*>)?($type:ty$(, $conv:ident)*) -> $field:ident),* $(,)?
    } => {$(
        $(#[$meta])*
        pub fn $name$(<$($param: $bound)*>)?(self, $field: $type) -> Self {
            Self(JwtClaims::<_> {
                $field: Some($field$(.$conv())*),
                ..self.0
            })
        }
    )*};
}

impl<Extra> JwtClaimsBuilder<Extra> {
    builder! {
        #[doc(alias = "iss")] issuer(impl Into<JwtUriClaim>, into) -> issuer,
        #[doc(alias = "sub")] subject(impl Into<JwtUriClaim>, into) -> subject,
        #[doc(alias = "aud")] audience(impl Into<JwtUriClaim>, into) -> audience,
        #[doc(alias = "exp")] expiration<Tz: TimeZone>(DateTime<Tz>, to_utc) -> expires,
        #[doc(alias = "nbf")] not_before<Tz: TimeZone>(DateTime<Tz>, to_utc) -> not_before,
        #[doc(alias = "iat")] issued_at<Tz: TimeZone>(DateTime<Tz>, to_utc) -> issued_at,
        #[doc(alias = "jti")] jwt_id(impl Into<String>, into) -> jwt_id,
    }

    pub fn build(self) -> JwtClaims<Extra> {
        self.0
    }
}

impl JwtClaimsBuilder<()> {
    pub fn then<Extra>(self, extra: Extra) -> JwtClaimsBuilder<Extra> {
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


pub trait RocketProvider: crate::Provider {
    fn make_responder<'r>(&self, error: Self::ClientError) -> impl Responder<'r, 'static>;

    fn oauth2(f: impl FnOnce(Oauth2Builder) -> Oauth2Builder) -> impl IntoIterator<Item = Route> where Self: oauth2::Oauth2 {
        let b = f(Oauth2Builder::default());

        [
            Route::new(Method::Post, b.token_endpoint.as_ref(), oauth2::oauth2_token::<Self>),
            Route::new(Method::Post, b.revoke_endpoint.as_ref(), oauth2::oauth2_revoke::<Self>)
        ]
    }

    fn jwk_key_set(_: impl FnOnce(()) -> ()) -> impl IntoIterator<Item = Route> where Self: oauth2::KeySet {
        [
            Route::new(Method::Get, "/.well-known/jwks.json", oauth2::jwk_key_set::<Self>)
        ]
    }

    #[doc(hidden)]
    fn routes() -> impl IntoIterator<Item = Route>;
}

pub struct Fairing<V: Provider> {
    provider: Arc<V>,
    mount_path: Origin<'static>,
}

impl<V: Provider> Fairing<V> {
    fn new(validator: impl Into<Arc<V>>, mount_path: impl Into<Origin<'static>>) -> Self {
        Self {
            provider: validator.into(),
            mount_path: mount_path.into(),
        }
    }
}

#[async_trait]
impl<V: Provider> rocket::fairing::Fairing for Fairing<V> {
    fn info(&self) -> Info {
        Info {
            name: "Identity",
            kind: Kind::Ignite
        }
    }

    async fn on_ignite(&self, rocket: Rocket<Build>) -> rocket::fairing::Result {
        Ok(rocket
            .manage(self.provider.clone())
            .mount(self.mount_path.clone(), V::routes().into_iter().collect::<Vec<_>>()))
    }
}

pub fn fairing<'a, V: Provider>(validator: impl Into<Arc<V>>, mount_path: impl TryInto<Origin<'static>, Error: Debug>) -> Fairing<V> {
    Fairing::<V>::new(validator, mount_path.try_into().unwrap())
}

#[derive(Error, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeneralError {
    #[error("not implemented")]
    NotImplemented,

    #[error("not authorized")]
    NotAuthorized,
}

pub struct Oauth2Builder {
    token_endpoint: Cow<'static, str>,
    revoke_endpoint: Cow<'static, str>,
}

impl Oauth2Builder {
    pub fn token_path(self, path: impl Into<Cow<'static, str>>) -> Self {
        Self {
            token_endpoint: path.into(),
            ..self
        }
    }

    pub fn revoke_path(self, path: impl Into<Cow<'static, str>>) -> Self {
        Self {
            revoke_endpoint: path.into(),
            ..self
        }
    }
}

impl Default for Oauth2Builder {
    fn default() -> Self {
        Self {
            token_endpoint: "/oauth2/token".into(),
            revoke_endpoint: "/oauth2/revoke".into()
        }
    }
}

#[async_trait]
#[allow(unused)]
pub trait Provider: Sized + Send + Sync + 'static {
    type ClientError: std::error::Error + From<GeneralError>;

    fn make_responder<'r>(&self, error: Self::ClientError) -> impl Responder<'r, 'static>;
    fn get_verifier<R: Role<Provider = Self>>(&self, alg: JwtAlgorithm, key_id: &'_ JwtHeader) -> Result<&(dyn VerifyToken<R> + Send + Sync), TokenVerifyError<R>>;

    fn find_authorization<'r>(&self, request: &'r Request<'_>) -> Option<&'r SecretStr> {
        get_bearer_authorization_header(request)
    }

    fn oauth2(f: impl FnOnce(Oauth2Builder) -> Oauth2Builder) -> impl IntoIterator<Item = Route> where Self: oauth2::Oauth2 {
        let b = f(Oauth2Builder::default());

        [
            Route::new(Method::Post, b.token_endpoint.as_ref(), oauth2::oauth2_token::<Self>),
            Route::new(Method::Post, b.revoke_endpoint.as_ref(), oauth2::oauth2_revoke::<Self>)
        ]
    }

    fn jwk_key_set(_: impl FnOnce(()) -> ()) -> impl IntoIterator<Item = Route> where Self: oauth2::KeySet {
        [
            Route::new(Method::Get, "/.well-known/jwks.json", oauth2::jwk_key_set::<Self>)
        ]
    }

    async fn sign<R: Role<Provider = Self>>(&self, token: R) -> Result<TokenSignResult, TokenSignError<R>> {
        let signer = token.get_signer(self);
        signer.sign_token(token).await
    }

    #[doc(hidden)]
    fn routes() -> impl IntoIterator<Item = Route>;
}

#[macro_export]
macro_rules! provider_routes {
    {
        $(use $($name:ident)::*$(($($pname:ident$(: $params:expr)?),* $(,)?))?);* $(;)?
    } => {
        #[doc(hidden)]
        fn routes() -> impl IntoIterator<Item = ::rocket::Route> {
            ::std::iter::empty::<::rocket::Route>()
                $(.chain($($name)::*(|__b| __b$($(.$pname($($params)?)),*)?)))*
        }
    };
}

pub trait Scope<S: ?Sized>: 'static {
    fn test(value: &S) -> bool;
    fn fmt(f: &mut std::fmt::Formatter) -> std::fmt::Result;

    fn display() -> impl Display {
        struct DisplayImpl<S: ?Sized, Sc: Scope<S> + ?Sized>(PhantomData<(*const Sc, S)>);

        impl<S: ?Sized, Sc: Scope<S> + ?Sized> Display for DisplayImpl<S, Sc> {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                <Sc as Scope<S>>::fmt(f)
            }
        }

        DisplayImpl::<S, Self>(PhantomData)
    }
}

#[doc(hidden)]
#[non_exhaustive]
pub struct AnyOf<T>(T);

#[doc(hidden)]
#[non_exhaustive]
pub struct AllOf<T>(T);

#[doc(hidden)]
#[non_exhaustive]
pub struct Not<T>(T);

impl<S: ?Sized, T: Scope<S>> Scope<S> for Not<T> {
    #[inline(always)]
    fn test(value: &S) -> bool {
        !T::test(value)
    }

    fn fmt(f: &mut Formatter) -> std::fmt::Result {
        f.write_char('!')?;
        T::fmt(f)
    }
}

#[doc(hidden)]
#[derive(Default)]
pub struct Const<const VALUE: bool>;

impl<S: ?Sized, const VALUE: bool> Scope<S> for Const<VALUE> {
    fn test(_: &S) -> bool {
        VALUE
    }

    fn fmt(f: &mut Formatter) -> std::fmt::Result {
        Display::fmt(&VALUE, f)
    }
}

#[doc(hidden)]
#[non_exhaustive]
pub struct Compose<T, Def = Const<false>>(T, Def);

macro_rules! gen_fmt {
    ($name:ident($($p:ident),*)) => {
        #[allow(unused, unused_assignments)]
        fn fmt(f: &mut Formatter) -> std::fmt::Result {
            f.write_str(concat!(stringify!($name), "("))?;

            let mut comma = false;
            $(
            if comma { f.write_str(", ")?; }
            else { comma = true; }
            $p::fmt(f)?;
            )*

            f.write_char(')')
        }
    };
}

macro_rules! scope_array {
    ($(<$($p:ident),* $(,)?>;)*) => {
        #[allow(unused_parens, non_snake_case)]
        const _: () = {$(
            impl<S: ?Sized, $($p: Scope<S>),*> Scope<S> for ($($p,)*) where AllOf<($($p,)*)>: Scope<S> {
                #[inline(always)]
                fn test(value: &S) -> bool {
                    AllOf::<($($p,)*)>::test(value)
                }

                fn fmt(f: &mut Formatter) -> std::fmt::Result {
                    AllOf::<($($p,)*)>::fmt(f)
                }
            }

            impl<S: ?Sized, $($p: Scope<S>),*> Scope<S> for AllOf<($($p,)*)> {
                #[inline(always)]
                fn test(value: &S) -> bool {
                    $(<$p as Scope<S>>::test(value))&&*
                }

                gen_fmt!(all($($p),*));
            }

            impl<S: ?Sized, $($p: Scope<S>),*> Scope<S> for AnyOf<($($p,)*)> {
                #[inline(always)]
                fn test(value: &S) -> bool {
                    $(<$p as Scope<S>>::test(value))||*
                }

                gen_fmt!(any($($p),*));
            }
        )*};
    };
}

macro_rules! compose_array {
    ($(<$($p:ident if $c:ident),* $(,)?>;)*) => {
        #[allow(unused_parens)]
        const _: () = {$(
            impl<S: ?Sized, Def: Scope<S>, $($p: Scope<S>, $c: Scope<S>),*> Scope<S> for Compose<($(($c, $p),)*), Def> {
                #[inline(always)]
                fn test(value: &S) -> bool {
                    $(if <$c as Scope<S>>::test(value) {
                        return <$p as Scope<S>>::test(value);
                    })*

                    <Def as Scope<S>>::test(value)
                }

                fn fmt(f: &mut Formatter) -> std::fmt::Result {
                    f.write_str("compose { ")?;

                    let mut comma = false;
                    $(
                    if comma { f.write_str(", ")?; }
                    else { comma = true; }
                    $c::fmt(f)?;
                    f.write_str(" => ")?;
                    $p::fmt(f)?;
                    )*

                    if ::std::any::TypeId::of::<Def>() != ::std::any::TypeId::of::<Const<false>>() {
                        if comma { f.write_str(", ")?; }
                        f.write_str("_ => ")?;
                        Def::fmt(f)?;
                    }

                    f.write_str(" }")
                }
            }
        )*};
    };
}

scope_array! {
    <T1>;
    <T1, T2>;
    <T1, T2, T3>;
    <T1, T2, T3, T4>;
    <T1, T2, T3, T4, T5>;
    <T1, T2, T3, T4, T5, T6>;
    <T1, T2, T3, T4, T5, T6, T7>;
    <T1, T2, T3, T4, T5, T6, T7, T8>;
    <T1, T2, T3, T4, T5, T6, T7, T8, T9>;
    <T1, T2, T3, T4, T5, T6, T7, T8, T9, T10>;
    <T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11>;
    <T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12>;
    <T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13>;
    <T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14>;
    <T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15>;
    <T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16>;
    <T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16, T17>;
    <T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16, T17, T18>;
    <T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16, T17, T18, T19>;
    <T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16, T17, T18, T19, T20>;
}

compose_array! {
    <T1 if C1>;
    <T1 if C1, T2 if C2>;
    <T1 if C1, T2 if C2, T3 if C3>;
    <T1 if C1, T2 if C2, T3 if C3, T4 if C4>;
    <T1 if C1, T2 if C2, T3 if C3, T4 if C4, T5 if C5>;
    <T1 if C1, T2 if C2, T3 if C3, T4 if C4, T5 if C5, T6 if C6>;
    <T1 if C1, T2 if C2, T3 if C3, T4 if C4, T5 if C5, T6 if C6, T7 if C7>;
    <T1 if C1, T2 if C2, T3 if C3, T4 if C4, T5 if C5, T6 if C6, T7 if C7, T8 if C8>;
    <T1 if C1, T2 if C2, T3 if C3, T4 if C4, T5 if C5, T6 if C6, T7 if C7, T8 if C8, T9 if C9>;
    <T1 if C1, T2 if C2, T3 if C3, T4 if C4, T5 if C5, T6 if C6, T7 if C7, T8 if C8, T9 if C9, T10 if C10>;
    <T1 if C1, T2 if C2, T3 if C3, T4 if C4, T5 if C5, T6 if C6, T7 if C7, T8 if C8, T9 if C9, T10 if C10, T11 if C11>;
    <T1 if C1, T2 if C2, T3 if C3, T4 if C4, T5 if C5, T6 if C6, T7 if C7, T8 if C8, T9 if C9, T10 if C10, T11 if C11, T12 if C12>;
    <T1 if C1, T2 if C2, T3 if C3, T4 if C4, T5 if C5, T6 if C6, T7 if C7, T8 if C8, T9 if C9, T10 if C10, T11 if C11, T12 if C12, T13 if C13>;
    <T1 if C1, T2 if C2, T3 if C3, T4 if C4, T5 if C5, T6 if C6, T7 if C7, T8 if C8, T9 if C9, T10 if C10, T11 if C11, T12 if C12, T13 if C13, T14 if C14>;
    <T1 if C1, T2 if C2, T3 if C3, T4 if C4, T5 if C5, T6 if C6, T7 if C7, T8 if C8, T9 if C9, T10 if C10, T11 if C11, T12 if C12, T13 if C13, T14 if C14, T15 if C15>;
    <T1 if C1, T2 if C2, T3 if C3, T4 if C4, T5 if C5, T6 if C6, T7 if C7, T8 if C8, T9 if C9, T10 if C10, T11 if C11, T12 if C12, T13 if C13, T14 if C14, T15 if C15, T16 if C16>;
    <T1 if C1, T2 if C2, T3 if C3, T4 if C4, T5 if C5, T6 if C6, T7 if C7, T8 if C8, T9 if C9, T10 if C10, T11 if C11, T12 if C12, T13 if C13, T14 if C14, T15 if C15, T16 if C16, T17 if C17>;
    <T1 if C1, T2 if C2, T3 if C3, T4 if C4, T5 if C5, T6 if C6, T7 if C7, T8 if C8, T9 if C9, T10 if C10, T11 if C11, T12 if C12, T13 if C13, T14 if C14, T15 if C15, T16 if C16, T17 if C17, T18 if C18>;
    <T1 if C1, T2 if C2, T3 if C3, T4 if C4, T5 if C5, T6 if C6, T7 if C7, T8 if C8, T9 if C9, T10 if C10, T11 if C11, T12 if C12, T13 if C13, T14 if C14, T15 if C15, T16 if C16, T17 if C17, T18 if C18, T19 if C19>;
    <T1 if C1, T2 if C2, T3 if C3, T4 if C4, T5 if C5, T6 if C6, T7 if C7, T8 if C8, T9 if C9, T10 if C10, T11 if C11, T12 if C12, T13 if C13, T14 if C14, T15 if C15, T16 if C16, T17 if C17, T18 if C18, T19 if C19, T20 if C20>;
}

#[macro_export]
macro_rules! allow {
    [] => { $crate::Const::<true> };
    [$scope:ty] => { $scope };
    [!$scope:ty] => { $crate::not!($scope) };
    [true] => { $crate::Const::<true> };
    [false] => { $crate::Const::<false> };
}

#[macro_export]
macro_rules! any {
    ($($($scope:ty)*),+) => { $crate::AnyOf::<($($crate::allow![$($scope)*],)*)> };
}

#[macro_export]
macro_rules! all {
    ($($($scope:ty)*),+) => { $crate::AllOf::<($($crate::allow![$($scope)*],)*)> };
}

#[macro_export]
macro_rules! not {
    ($scope:ty) => { $crate::Not::<$crate::allow![$scope]> };
}

#[macro_export]
macro_rules! compose {
    (_ => $scope:ty) => { $scope };
    ($condition:ty => $scope:ty) => { $crate::all!($condition, $scope) };
    ($($condition:ty => $scope:ty),* $(, $(@ => $default:ty)?)?) => {
        $crate::Compose::<($(($condition, $scope),)*)$($(, $default)?)?>
    };
}

#[macro_export]
macro_rules! deny {
    [] => { $crate::Const::<false> };
    ($($tt:tt)+) => { $crate::not!($crate::allow!($($tt)*)) };
}

pub fn get_bearer_authorization_header<'r>(request: &'r Request<'_>) -> Option<&'r SecretStr> {
    request.headers().get_one("Authorization").and_then(|header| header.split_once(' ')
        .and_then(|v| match v.0 {
            "Bearer" => Some(SecretStr::new(v.1)),
            _ => None
        }))
}

#[async_trait]
pub trait Role: Sized + Send + Sync + Debug + Display + 'static {
    type Provider: Provider;
    type Scope: ?Sized;
    type ValidationError: std::error::Error + Send + Sync;
    type ClaimsExtra: Serialize + DeserializeOwned;

    fn into_claims(self) -> Result<JwtClaims<Self::ClaimsExtra>, Self::ValidationError>;
    async fn from_claims(provider: &Self::Provider, claims: JwtClaims<Self::ClaimsExtra>) -> Result<Self, Self::ValidationError>;

    fn scope(&self) -> &Self::Scope;
    fn get_signer<'p>(&'_ self, provider: &'p Self::Provider) -> &'p (dyn SignToken<Self> + Send + Sync);
}

pub struct Bearer<R: Role, Scopes: Scope<R::Scope> = allow![true]> {
    pub role: R,
    _phantom: PhantomData<Scopes>,
}

#[async_trait]
impl<'r, R: Role, Scopes: Scope<R::Scope>> FromRequest<'r> for Bearer<R, Scopes> {
    type Error = TokenVerifyError<R>;

    #[cfg_attr(feature = "tracing-instrument", tracing::instrument(
        skip(request),
        level = "DEBUG",
        name = "Bearer::from_request",
        fields(
            role = %std::any::type_name::<R>(),
            scopes = %Scopes::display(),
        )
    ))]
    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let provider = request.rocket().state::<Arc<R::Provider>>().unwrap();
        match provider.find_authorization(request) {
            None => {
                tracing::debug!("Forwarding as no authorization was provided");
                Outcome::Forward(Status::Unauthorized)
            },
            Some(token) => {
                if let Some((header, _)) = token.split_once('.') {
                    let mut bytes = Vec::<u8>::new();
                    match Decoder::<Base64UrlUnpadded>::new(header.expose_bytes())
                        .and_then(|mut v| v.decode_to_end(&mut bytes))
                    {
                        Ok(_) => {},
                        Err(e) => {
                            tracing::warn!("Failed to decode token header, rejecting: {e}");
                            return Outcome::Error((Status::BadRequest, TokenVerifyError::Base64(e)));
                        }
                    };

                    let jwt_header: JwtHeader = match serde_json::from_slice(bytes.as_slice()) {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!("Failed to deserialize token header, rejecting: {e}");
                            return Outcome::Error((Status::BadRequest, TokenVerifyError::Serialization(e)));
                        }
                    };

                    if jwt_header.typ != JwtType::JWT {
                        tracing::warn!("Provided authorization was not a JWT, it is {:?}", jwt_header.typ);
                        return Outcome::Error((Status::BadRequest, TokenVerifyError::NotJWT))
                    }

                    let res = match provider.get_verifier::<R>(jwt_header.alg, &jwt_header) {
                        Ok(baker) => baker.verify_token(provider, token).await,
                        Err(e) => Err(e)
                    };

                    match res {
                        Ok(role) => {
                            if Scopes::test(role.scope()) {
                                tracing::info!(%role, "Passed authorization gate");
                                Outcome::Success(Bearer { role, _phantom: PhantomData })
                            } else {
                                tracing::warn!(%role, "Missing scopes, rejecting (did not match: {})", Scopes::display());
                                Outcome::Error((Status::Forbidden, TokenVerifyError::MissingScopes(Scopes::display().to_string())))
                            }
                        },
                        Err(e) => {
                            tracing::warn!("Token verification error: {e}");
                            Outcome::Error((Status::Forbidden, e))
                        }
                    }
                } else {
                    tracing::debug!("Detected authorization was not a JWT");
                    Outcome::Forward(Status::BadRequest)
                }
            }
        }
    }
}

#[macro_export]
#[allow(non_snake_case)]
macro_rules! Bearer {
    [$role:ty$(, $($scopes:tt)*)?] => {
        $crate::Bearer::<$role$(, $crate::allow![$($scopes)*])?>
    };
}

pub trait ConstStr: 'static {
    const VALUE: &'static str;
}

impl<S: Borrow<str> + Eq + Hash, C: ConstStr> Scope<HashSet<S>> for C {
    #[inline(always)]
    fn test(value: &HashSet<S>) -> bool {
        value.contains(C::VALUE)
    }

    fn fmt(f: &mut Formatter) -> std::fmt::Result {
        write!(f, "has<{}>", C::VALUE)
    }
}

impl<S: Borrow<str> + Ord, C: ConstStr> Scope<BTreeSet<S>> for C {
    #[inline(always)]
    fn test(value: &BTreeSet<S>) -> bool {
        value.contains(C::VALUE)
    }

    fn fmt(f: &mut Formatter) -> std::fmt::Result {
        write!(f, "has<{}>", C::VALUE)
    }
}

impl<S: Borrow<str> + Eq, C: ConstStr> Scope<[S]> for C {
    #[inline(always)]
    fn test(value: &[S]) -> bool {
        for v in value {
            if v.borrow() == C::VALUE {
                return true;
            }
        }

        false
    }

    fn fmt(f: &mut Formatter) -> std::fmt::Result {
        write!(f, "has<{}>", C::VALUE)
    }
}

impl<S: Borrow<str> + Eq, C: ConstStr, const LEN: usize> Scope<[S; LEN]> for C {
    #[inline(always)]
    fn test(value: &[S; LEN]) -> bool {
        for v in value {
            if v.borrow() == C::VALUE {
                return true;
            }
        }

        false
    }

    fn fmt(f: &mut Formatter) -> std::fmt::Result {
        write!(f, "has<{}>", C::VALUE)
    }
}

#[macro_export]
macro_rules! const_str {
    {$($(#[$meta:meta])* $vis:vis type $name:ident = $value:expr;)*} => {$(
        $(#[$meta])*
        $vis enum $name {}

        impl $crate::ConstStr for $name {
            const VALUE: &'static str = $value;
        }
    )*};
}

#[cfg(test)]
mod tests {
    use crate::Scope;

    const_str! {
        type AllowTest = "test";
        type AllowCool = "cool";
        type AllowOpenID = "openid";
    }

    #[test]
    fn always_true() {
        assert_eq!(<allow![true]>::test(&["test"]), true);
    }

    #[test]
    fn always_false() {
        assert_eq!(<allow![false]>::test(&["test"]), false);
    }

    #[test]
    fn scope_test() {
        assert_eq!(<allow![AllowTest]>::test(&["test"]), true);
        assert_eq!(<allow![AllowTest]>::test(&["cool"]), false);
    }

    #[test]
    fn scope_any_of() {
        assert_eq!(<allow![any!(AllowTest, AllowCool)]>::test(&["test"]), true);
        assert_eq!(<allow![any!(AllowTest, AllowCool)]>::test(&["cool"]), true);
        assert_eq!(<allow![any!(AllowTest, AllowCool)]>::test(&["test", "cool"]), true);
        assert_eq!(<allow![any!(AllowTest, AllowCool)]>::test(&["openid"]), false);
    }

    #[test]
    fn scope_all_of() {
        assert_eq!(<allow![all!(AllowTest, AllowCool)]>::test(&["test"]), false);
        assert_eq!(<allow![all!(AllowTest, AllowCool)]>::test(&["cool"]), false);
        assert_eq!(<allow![all!(AllowTest, AllowCool)]>::test(&["test", "cool"]), true);
    }

    #[test]
    fn scope_not() {
        assert_eq!(<allow![!AllowTest]>::test(&["test"]), false);
        assert_eq!(<allow![!AllowCool]>::test(&["test"]), true);

        assert_eq!(<deny![AllowTest]>::test(&["test"]), false);
        assert_eq!(<deny![AllowCool]>::test(&["test"]), true);
    }

    #[test]
    fn scope_compose() {
        assert_eq!(<compose! { _ => allow![true] }>::test(&["test"]), true);
        assert_eq!(<compose! { _ => allow![false] }>::test(&["test"]), false);

        assert_eq!(<compose! { AllowTest => AllowCool }>::test(&["test"]), false);
        assert_eq!(<compose! { AllowTest => AllowCool }>::test(&["cool"]), false);
        assert_eq!(<compose! { AllowTest => AllowCool }>::test(&["test", "cool"]), true);

        type Composed = compose! {
            AllowTest => allow![],
            AllowCool => deny![],
            @ => AllowOpenID
        };

        assert_eq!(Composed::test(&["test"]), true);
        assert_eq!(Composed::test(&["test", "cool"]), true);
        assert_eq!(Composed::test(&["cool"]), false);
        assert_eq!(Composed::test(&["openid"]), true);
        assert_eq!(Composed::test(&["openid", "cool"]), false);
        assert_eq!(Composed::test(&["openid", "cool", "test"]), true);
    }
}
