use chrono::{DateTime, Duration, Utc};
use rocket::response::Responder;
use rocket::serde::json::Json;
use rocket::{Build, Rocket, async_trait, routes};
use rocket_identity::RefOrOwned::Ref;
use rocket_identity::oauth2::{KeySet, Oauth2, Oauth2Error, Oauth2Response};
use rocket_identity::tokens::{
    ES256, HS256, PrivateKey, RS256, SignToken, TokenVerifyError, VerifyToken,
};
use rocket_identity::{
    Bearer, GeneralError, JwkContent, JwtAlgorithm, JwtClaims, JwtHeader, Provider, Role, allow,
    const_str, provider_routes,
};
use rocket_identity::{RefOrOwned, SecretStr};
use rsa::pkcs8::DecodePrivateKey;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashSet;
use std::convert::Infallible;
use std::fmt::{Display, Formatter};
use thiserror::Error;

const_str! {
    type Miaw = "miaw";
}

const PEM: &str = include_str!("rsatestkey.pem");

pub fn rocket() -> Rocket<Build> {
    rocket::build()
        .attach(rocket_identity::fairing(
            TestProvider {
                hs256: HS256::new(SecretStr::new("secret")),
                rs256: RS256::<PrivateKey>::from_key(
                    rsa::pkcs1v15::SigningKey::from_pkcs8_pem(PEM).unwrap(),
                ),
                es256: ES256::<PrivateKey>::random_with_id("user"),
            },
            "/",
        ))
        .mount("/", routes![test, miaw])
}

#[rocket::get("/test")]
fn test(auth: Bearer![TestRole]) -> String {
    let sub = auth.role.claims.subject.as_deref().unwrap();
    format!("Hello, {sub}!")
}

#[rocket::get("/miaw")]
fn miaw(auth: Bearer![TestRole, Miaw]) -> String {
    let sub = auth.role.claims.subject.as_deref().unwrap();
    format!("Miaw, {sub}!")
}

pub struct TestProvider {
    hs256: HS256,
    rs256: RS256<PrivateKey>,
    es256: ES256<PrivateKey>,
}

#[derive(Error, Debug, Serialize)]
pub enum Error {
    #[error("general error: {0}")]
    General(#[from] GeneralError),
}

impl Provider for TestProvider {
    type ClientError = Error;
    type HeaderExtra = ();

    fn make_responder<'r>(&self, error: Self::ClientError) -> impl Responder<'r, 'static> {
        Json(error)
    }

    fn get_verifier<R: Role<Provider = Self, HeaderExtra = Self::HeaderExtra>>(
        &'_ self,
        alg: JwtAlgorithm,
        _: &JwtHeader,
    ) -> Result<RefOrOwned<'_, dyn VerifyToken<R> + Send + Sync>, TokenVerifyError<R>> {
        match alg {
            JwtAlgorithm::HS256 => Ok(Ref(&self.hs256)),
            other => Err(TokenVerifyError::UnsupportedAlgorithm(other)),
        }
    }

    provider_routes! {
        use Self::oauth2();
        use Self::jwk_key_set();
    }
}

impl KeySet for TestProvider {
    #[allow(deprecated)]
    fn get_key_set(&self) -> impl IntoIterator<Item = JwkContent> {
        [
            self.rs256.as_key(),
            self.rs256.as_private_key_exposed(),
            self.es256.as_key(),
            self.es256.as_private_key_exposed(),
        ]
    }
}

#[derive(Debug)]
pub struct TestRole {
    pub claims: JwtClaims,
    pub scopes: HashSet<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RoleExtra {
    pub scopes: HashSet<String>,
}

impl Display for TestRole {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.claims.subject.as_deref().unwrap())
    }
}

#[async_trait]
impl Role for TestRole {
    type Provider = TestProvider;
    type Scope = HashSet<String>;
    type ValidationError = Infallible;
    type ClaimsExtra = RoleExtra;
    type HeaderExtra = ();

    fn into_claims(self) -> Result<JwtClaims<Self::ClaimsExtra>, Self::ValidationError> {
        Ok(self.claims.with(RoleExtra {
            scopes: self.scopes,
        }))
    }

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

    fn scope(&self) -> &Self::Scope {
        &self.scopes
    }

    fn get_signer<'p>(
        &'_ self,
        provider: &'p Self::Provider,
    ) -> RefOrOwned<'p, dyn SignToken<Self> + Send + Sync> {
        Ref(&provider.hs256)
    }
}

#[async_trait]
impl Oauth2 for TestProvider {
    type ExtraResponse = ();

    #[cfg_attr(feature = "tracing-instrument", tracing::instrument(skip_all))]
    async fn token_from_resource_owner_password(
        &self,
        client_id: &str,
        client_secret: &SecretStr,
        username: &str,
        password: &SecretStr,
        scopes: &[&str],
    ) -> Result<Oauth2Response<Self::ExtraResponse>, Oauth2Error> {
        tracing::info!(client_id, client_secret = ?client_secret.expose(), username, password = ?password.expose(), ?scopes);
        let resp = self
            .sign(TestRole {
                claims: JwtClaims::new()
                    .issuer("https://example.com")
                    .audience("nobody")
                    .subject(username)
                    .expiration(Utc::now() + Duration::minutes(15))
                    .issued_at(Utc::now())
                    .build(),
                scopes: scopes.iter().map(|s| s.to_string()).collect(),
            })
            .await?;

        Ok(Oauth2Response::new(resp.token, "bearer", resp.expires))
    }
}
