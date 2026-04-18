use chrono::TimeDelta;
use rocket::response::Responder;
use rocket::serde::json::Json;
use rocket::serde::{Deserialize, Serialize};
use rocket::{async_trait, routes};
use rocket_identity::{
    Bearer, GeneralError, Provider,
    RefOrOwned::{self, Ref},
    Role, SecretStr, const_str,
    oauth2::{Oauth2, Oauth2Error, Oauth2Response},
    provider_routes,
    jwt::{JwtAlgorithm, JwtClaims, JwtHeader},
    tokens::{
        // Token implementations require enabling feature flags.
        // HS256 requires the `hs256` flag and will pull in `hmac` and `sha2`.
        HS256,
        SignToken,
        TokenSignResult,
        TokenVerifyError,
        VerifyToken,
    },
};
use std::collections::HashSet;
use std::convert::Infallible;
use std::fmt::{Display, Formatter};

// const_str! defines string constants as types.
//
// This is very useful for this crate, as scope requirement are represented
// as type parameters of the [Bearer] type.
const_str! {
    /// If the scopes include the string "test", the test passes and
    /// [rocket_identity::Scope::test] will return `true`. Otherwise,
    /// `false` is returned.
    ///
    /// These values may be augmented by various modifiers.
    type HasTest = "test";
}

#[rocket::launch]
pub fn launch() -> _ {
    rocket::build()
        .attach(rocket_identity::fairing(
            TestProvider {
                hs256: HS256::new(SecretStr::new("secret")),
            },
            "/",
        ))
        .mount("/", routes![test])
}

/// This [Bearer] guard is the main component of this crate. The first
/// parameter is the [Role] implementation that will be deserialized and
/// validated. The second parameter is optional, and will use the
/// [rocket_identity::Scope] implementation on the provided type to perform
/// tests on the [Role::scope] value before allowing the guard to succeed.
///
/// Scope requirements can be composed as described in [Bearer] to
/// represent more complex requirements. Additionally, you can implement
/// [rocket_identity::Scope] manually if necessary.
#[rocket::get("/test")]
fn test(auth: Bearer![TestRole, HasTest]) -> String {
    let sub = auth.claims.subject.as_deref().unwrap();
    format!("Hello, {sub}!")
}

/// The entry point of this crate. [Provider]s contain necessary [VerifyToken]
/// implementations for checking authorization, and may contain extra things
/// like database access that will be passed to [Role]s.
pub struct TestProvider {
    hs256: HS256,
}

impl Provider for TestProvider {
    type ClientError = Error;
    type HeaderExtra = ();

    fn make_responder<'r>(&self, error: Self::ClientError) -> impl Responder<'r, 'static> {
        Json(error)
    }

    /// This method must return the (most) correct [VerifyToken] implementation
    /// that will be used to validate the token.
    ///
    /// For the most part, just `alg` is needed to find the correct token, but
    /// if you're using the `kid` (key ID) header field you can access that
    /// here to find the correct verifier.
    fn get_verifier<R: Role<Provider = Self, HeaderExtra = Self::HeaderExtra>>(
        &'_ self,
        alg: JwtAlgorithm,
        header: &JwtHeader,
    ) -> Result<RefOrOwned<'_, dyn VerifyToken<R> + Send + Sync>, TokenVerifyError<R>> {
        match alg {
            JwtAlgorithm::HS256 => Ok(Ref(&self.hs256)),
            other => Err(TokenVerifyError::UnsupportedAlgorithm(other)),
        }
    }

    // This macro implements routes() by composing some builtin routes
    // together. This allows reusing the OAuth2 implementation in this crate
    // easily.
    //
    // These route sets also support configuration:
    // > use Self::oauth2(revoke_path: "/auth/revoke", token_path: "/auth/token");
    provider_routes! {
        use Self::oauth2();
    }
}

/// A [Role] is a structured representation of a client's permissions and any
/// additional information (derived or included in a JWT) that is needed to
/// perform requested actions.
#[derive(Debug)]
pub struct TestRole {
    pub claims: JwtClaims,
    pub scopes: HashSet<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RoleExtra {
    pub scopes: HashSet<String>,
}

/// [Role]s must implement [Display]. This will be logged using the [tracing]
/// crate, so ensure that the implementation is sufficiently anonymized for
/// your needs.
impl Display for TestRole {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.claims.subject.as_deref().unwrap())
    }
}

/// Roles are a set of claims that can be serialized and deserialized from
/// a JWT's claims.
#[async_trait]
impl Role for TestRole {
    type Provider = TestProvider;
    type Scope = HashSet<String>;
    type ValidationError = Infallible;
    type ClaimsExtra = RoleExtra;
    type HeaderExtra = ();

    /// Converts this Role into a JWT's claims. The token will then be signed
    /// immediately afterward and returned to the client.
    ///
    /// This method is only called if the client passes authorization checks
    /// and may be granted a token.
    fn into_claims(self) -> Result<JwtClaims<Self::ClaimsExtra>, Self::ValidationError> {
        Ok(self.claims.with(RoleExtra {
            scopes: self.scopes,
        }))
    }

    /// Creates this Role from the provided JWT claims.
    ///
    /// See [JwtClaims] for the set of recognized claims. The
    /// [Self::ClaimsExtra] type should serialize to an object and can contain
    /// any information you wish to include in the token, but cannot be
    /// represented by the [JwtClaims] type. (e.g. scopes)
    async fn from_claims(
        _provider: &Self::Provider,
        claims: JwtClaims<Self::ClaimsExtra>,
    ) -> Result<Self, Self::ValidationError> {
        let (claims, extra) = claims.split();
        Ok(Self {
            claims,
            scopes: extra.scopes,
        })
    }

    /// Called by the [BearerToken] guard to ensure this token is as permissive
    /// as required.
    fn scope(&self) -> &Self::Scope {
        &self.scopes
    }

    /// The role should return a reference to the [SignToken] implementation
    /// that should be used to sign the resulting token.
    fn get_signer<'p>(
        &'_ self,
        provider: &'p Self::Provider,
    ) -> RefOrOwned<'p, dyn SignToken<Self> + Send + Sync> {
        Ref(&provider.hs256)
    }
}

#[async_trait]
impl Oauth2 for TestProvider {
    /// This type contains additional fields to include on a successful
    /// response, which can be populated via [Oauth2Response::new_with].
    type ExtraResponse = ();

    async fn token_from_resource_owner_password(
        &self,
        client_id: &str,
        client_secret: &SecretStr,
        username: &str,
        password: &SecretStr,
        scopes: &[&str],
    ) -> Result<Oauth2Response<Self::ExtraResponse>, Oauth2Error> {
        // Here you would need to validate the credentials with some database
        // or other authentication framework / service.

        // If everything is in order, build the token like so:
        let resp: TokenSignResult = self
            .sign(TestRole {
                claims: JwtClaims::new()
                    .issuer("https://example.com")
                    .audience(client_id)
                    .subject(username)
                    .issued_now()
                    .expires_in(TimeDelta::minutes(15))
                    .build(),

                // NOTE: this unsafely adds all requested scopes to the token
                // shouldn't need to be said but don't do this in prod!
                scopes: scopes.iter().map(|s| s.to_string()).collect(),
            })
            .await?;

        // OAuth2 response can be constructed by into(), which will be
        // serialized and returned to the client.
        Ok(resp.into())
    }
}

#[derive(Debug, Serialize)]
pub enum Error {
    General(GeneralError),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::General(e) => write!(f, "general error: {}", e),
        }
    }
}

impl std::error::Error for Error {}

impl From<GeneralError> for Error {
    fn from(e: GeneralError) -> Self {
        Error::General(e)
    }
}
