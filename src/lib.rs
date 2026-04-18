//! # rocket-identity
//!
//! This crate implements OAuth2 and JWT signing / verifying for managing
//! authorization in Rocket applications.
//!
//! cool features:
//! - Support for HMAC with SHA, ECDSA, and RSA (PKCS#1 v1.5 and PSS)
//! - Custom fields in returned tokens
//! - Static type based validation for scopes
//!
//! ## Security notice
//!
//! This crate has not been audited or security tested in itself.
//! Use at your own risk!
//!
//! ## Usage
//!
//! See [this example](https://github.com/der-fruhling/rocket-identity/blob/master/examples/readme.rs)
//! for usage instructions!

use crate::tokens::{SignToken, TokenSignError, TokenSignResult, TokenVerifyError, VerifyToken};
use crate::jwt::{JwtAlgorithm, JwtClaims, JwtHeader, JwtType};
use crate::scope::Scope;
use base64ct::{Base64UrlUnpadded, Decoder};
use chrono::{DateTime, TimeDelta, TimeZone, Utc};
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
use std::ops::{Add, Deref, DerefMut};
use std::sync::Arc;
use thiserror::Error;
use url::Url;
use keys::JwkContent;

#[cfg(test)]
mod tests;

pub mod oauth2;
pub mod oidc;
mod secret;
pub mod tokens;
pub mod keys;
pub mod scope;
pub mod jwt;

pub use secret::{AuthorizationHeader, SecretStr};

/// Allows overriding parts of a value on demand.
///
/// This is used to allow [Provider::sign_with] to take an override header
/// which contains data relevant to finding the correct key for validation,
/// or for a shortcut to deny invalid tokens.
pub trait Combine {
    /// Combines `self` and `other`, preferring the fields in `other` if set.
    ///
    /// If `Self` implements [Default] and `other` == [Default::default], then
    /// this method should return `self` without any changes.
    fn with(&self, other: Self) -> Self;
}

impl Combine for () {
    fn with(&self, _: Self) -> Self {
        ()
    }
}

/// A serde serializer to encode [DateTime]<[Utc]> as UNIX timestamps.
///
/// This serializer must be passed [Option] instead of just [DateTime] to
/// support optional fields.
///
/// ```
/// # use chrono::{DateTime, Utc};
/// # use serde::{Deserialize, Serialize};
/// #
/// #[derive(Serialize, Deserialize)]
/// struct Structure {
///     #[serde(with = "rocket_identity::datetime_serializer")]
///     time: Option<DateTime<Utc>>
/// }
///
/// # fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
/// let s = Structure { time: DateTime::<Utc>::from_timestamp(123456, 0) };
/// let json = serde_json::to_string(&s)?;
/// assert_eq!(json, r#"{"time":123456}"#);
/// # Ok(())
/// # }
pub mod datetime_serializer {
    use chrono::{DateTime, Utc};
    use serde::de::Error;
    use serde::{Deserializer, Serializer};
    use std::fmt::Formatter;

    pub fn serialize<S: Serializer>(
        date_time: &Option<DateTime<Utc>>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match date_time {
            None => s.serialize_none(),
            Some(v) => s.serialize_i64(v.timestamp()),
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
            E: Error,
        {
            DateTime::from_timestamp_secs(v)
                .map(Some)
                .ok_or_else(|| E::custom("invalid timestamp"))
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

/// The main [Rocket Fairing][rocket::fairing::Fairing] of this crate.
///
/// [Attach][rocket::rkt::Rocket::<rocket::phase::Build>::attach] this to your
/// Rocket instance to enable this crate's features.
///
/// Create via [rocket_identity::fairing][fairing].
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
            kind: Kind::Ignite,
        }
    }

    async fn on_ignite(&self, rocket: Rocket<Build>) -> rocket::fairing::Result {
        Ok(rocket.manage(self.provider.clone()).mount(
            self.mount_path.clone(),
            V::routes().into_iter().collect::<Vec<_>>(),
        ))
    }
}

/// Creates a [fairing][rocket::fairing::Fairing] instance to start using this
/// crate!
///
/// The `provider` argument must be your implementation of [Provider]. The
/// fairing will automatically manage an [Arc<V>] for you, which can be
/// accessed just like any other state:
///
/// ```
/// # use std::sync::Arc;
/// # use rocket::response::Responder;
/// # use rocket::{Build, Rocket, Route, State};
/// # use rocket::http::Status;
/// # use rocket::serde::json::Json;
/// # use rocket_identity::{GeneralError, Provider, RefOrOwned, Role};
/// # use rocket_identity::jwt::{JwtAlgorithm, JwtHeader};
/// # use rocket_identity::tokens::{TokenVerifyError, VerifyToken};
/// #
/// /* #[rocket::launch] */
/// fn rocket() -> Rocket<Build> {
///     rocket::build()
///         .attach(rocket_identity::fairing(YourProvider { /* ... */ }, "/"))
///         .mount("/", rocket::routes![access])
/// }
///
/// #[rocket::get("/access")]
/// fn access(state: &State<Arc<YourProvider>>) {
///     /* ... */
/// }
///
/// # let client = rocket::local::blocking::Client::tracked(rocket()).unwrap();
/// # let resp = client.get("/access").dispatch();
/// # assert_eq!(resp.status(), Status::Ok);
/// #
/// struct YourProvider { /* ... */ };
///
/// impl Provider for YourProvider {
///     /* ... */
/// #   type ClientError = GeneralError;
/// #   type HeaderExtra = ();
/// #
/// #   fn make_responder<'r>(&self, error: Self::ClientError) -> impl Responder<'r, 'static> {
/// #       Json(error)
/// #   }
/// #
/// #   fn get_verifier<R: Role<Provider=Self, HeaderExtra=Self::HeaderExtra>>(&'_ self, alg: JwtAlgorithm, key_id: &JwtHeader) -> Result<RefOrOwned<'_, dyn VerifyToken<R> + Send + Sync>, TokenVerifyError<R>> {
/// #       unimplemented!()
/// #   }
/// #
/// #   fn routes() -> impl IntoIterator<Item=Route> {
/// #       []
/// #   }
/// }
/// ```
///
/// [Attach][rocket::rkt::Rocket::<rocket::phase::Build>::attach] this to your
/// Rocket instance to enable this crate's features.
pub fn fairing<'a, V: Provider>(
    provider: impl Into<Arc<V>>,
    mount_path: impl TryInto<Origin<'static>, Error: Debug>,
) -> Fairing<V> {
    Fairing::<V>::new(provider, mount_path.try_into().unwrap())
}

#[derive(
    Error, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash, Serialize, Deserialize,
)]
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
            revoke_endpoint: "/oauth2/revoke".into(),
        }
    }
}

#[async_trait]
#[allow(unused)]
pub trait Provider: Sized + Send + Sync + 'static {
    type ClientError: std::error::Error + From<GeneralError>;
    type HeaderExtra: Serialize + DeserializeOwned + Combine + Send + Sync;

    fn make_responder<'r>(&self, error: Self::ClientError) -> impl Responder<'r, 'static>;
    fn get_verifier<R: Role<Provider = Self, HeaderExtra = Self::HeaderExtra>>(
        &'_ self,
        alg: JwtAlgorithm,
        key_id: &JwtHeader,
    ) -> Result<RefOrOwned<'_, dyn VerifyToken<R> + Send + Sync>, TokenVerifyError<R>>;

    fn find_authorization<'r>(&self, request: &'r Request<'_>) -> Option<&'r SecretStr> {
        get_bearer_authorization_header(request)
    }

    fn oauth2(f: impl FnOnce(Oauth2Builder) -> Oauth2Builder) -> impl IntoIterator<Item = Route>
    where
        Self: oauth2::Oauth2,
    {
        let b = f(Oauth2Builder::default());

        [
            Route::new(
                Method::Post,
                b.token_endpoint.as_ref(),
                oauth2::oauth2_token::<Self>,
            ),
            Route::new(
                Method::Post,
                b.revoke_endpoint.as_ref(),
                oauth2::oauth2_revoke::<Self>,
            ),
        ]
    }

    fn jwk_key_set(_: impl FnOnce(()) -> ()) -> impl IntoIterator<Item = Route>
    where
        Self: oauth2::KeySet,
    {
        [Route::new(
            Method::Get,
            "/.well-known/jwks.json",
            oauth2::jwk_key_set::<Self>,
        )]
    }

    async fn sign<R: Role<Provider = Self>>(
        &self,
        token: R,
    ) -> Result<TokenSignResult, TokenSignError<R>> {
        let signer = token.get_signer(self);
        signer.sign_token(token, None).await
    }

    async fn sign_with<R: Role<Provider = Self>>(
        &self,
        token: R,
        header_overrides: JwtHeader<R::HeaderExtra>,
    ) -> Result<TokenSignResult, TokenSignError<R>> {
        let signer = token.get_signer(self);
        signer.sign_token(token, Some(header_overrides)).await
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

pub fn get_bearer_authorization_header<'r>(request: &'r Request<'_>) -> Option<&'r SecretStr> {
    request
        .headers()
        .get_one("Authorization")
        .and_then(|header| {
            header.split_once(' ').and_then(|v| match v.0 {
                "Bearer" => Some(SecretStr::new(v.1)),
                _ => None,
            })
        })
}

#[async_trait]
pub trait Role: Sized + Send + Sync + Debug + Display + 'static {
    type Provider: Provider<HeaderExtra = Self::HeaderExtra>;
    type Scope: ?Sized;
    type ValidationError: std::error::Error + Send + Sync;
    type ClaimsExtra: Serialize + DeserializeOwned;
    type HeaderExtra: Serialize + DeserializeOwned + Send + Sync;

    fn into_claims(self) -> Result<JwtClaims<Self::ClaimsExtra>, Self::ValidationError>;
    async fn from_claims(
        provider: &Self::Provider,
        claims: JwtClaims<Self::ClaimsExtra>,
    ) -> Result<Self, Self::ValidationError>;

    fn construct_header(claims: &JwtClaims<Self::ClaimsExtra>, overrides: Option<JwtHeader<Self::HeaderExtra>>) -> Option<JwtHeader<Self::HeaderExtra>> {
        overrides
    }

    fn scope(&self) -> &Self::Scope;
    fn get_signer<'p>(
        &'_ self,
        provider: &'p Self::Provider,
    ) -> RefOrOwned<'p, dyn SignToken<Self> + Send + Sync>;
}

pub struct BearerToken<R: Role, Scopes: Scope<R::Scope> = allow![true]> {
    role: R,
    _phantom: PhantomData<Scopes>,
}

impl<R: Role, Scopes: Scope<R::Scope>> Deref for BearerToken<R, Scopes> {
    type Target = R;

    fn deref(&self) -> &Self::Target {
        &self.role
    }
}

impl<R: Role, Scopes: Scope<R::Scope>> DerefMut for BearerToken<R, Scopes> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.role
    }
}

#[async_trait]
impl<'r, R: Role, Scopes: Scope<R::Scope>> FromRequest<'r> for BearerToken<R, Scopes> {
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
            }
            Some(token) => {
                if let Some((header, _)) = token.split_once('.') {
                    let mut bytes = Vec::<u8>::new();
                    match Decoder::<Base64UrlUnpadded>::new(header.expose_bytes())
                        .and_then(|mut v| v.decode_to_end(&mut bytes))
                    {
                        Ok(_) => {}
                        Err(e) => {
                            tracing::warn!("Failed to decode token header, rejecting: {e}");
                            return Outcome::Error((
                                Status::BadRequest,
                                TokenVerifyError::Base64(e),
                            ));
                        }
                    };

                    let jwt_header: JwtHeader = match serde_json::from_slice(bytes.as_slice()) {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!("Failed to deserialize token header, rejecting: {e}");
                            return Outcome::Error((
                                Status::BadRequest,
                                TokenVerifyError::Serialization(e),
                            ));
                        }
                    };

                    if jwt_header.typ != JwtType::JWT {
                        tracing::warn!(
                            "Provided authorization was not a JWT, it is {:?}",
                            jwt_header.typ
                        );
                        return Outcome::Error((Status::BadRequest, TokenVerifyError::NotJWT));
                    }

                    let res = match provider.get_verifier::<R>(jwt_header.alg, &jwt_header) {
                        Ok(baker) => baker.verify_token(provider, token).await,
                        Err(e) => Err(e),
                    };

                    match res {
                        Ok(role) => {
                            if Scopes::test(role.scope()) {
                                tracing::info!(%role, "Passed authorization gate");
                                Outcome::Success(BearerToken {
                                    role,
                                    _phantom: PhantomData,
                                })
                            } else {
                                tracing::warn!(%role, "Missing scopes, rejecting (did not match: {})", Scopes::display());
                                Outcome::Error((
                                    Status::Forbidden,
                                    TokenVerifyError::MissingScopes(Scopes::display().to_string()),
                                ))
                            }
                        }
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
        $crate::BearerToken::<$role$(, $crate::allow![$($scopes)*])?>
    };
}

pub enum RefOrOwned<'p, T: ?Sized> {
    Ref(&'p T),
    Owned(Box<T>),
}

impl<T: ?Sized> AsRef<T> for RefOrOwned<'_, T> {
    fn as_ref(&self) -> &T {
        match self {
            RefOrOwned::Ref(v) => v,
            RefOrOwned::Owned(v) => v,
        }
    }
}

impl<T: ?Sized> Deref for RefOrOwned<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self {
            RefOrOwned::Ref(v) => v,
            RefOrOwned::Owned(v) => v,
        }
    }
}


