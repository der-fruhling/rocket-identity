# rocket-identity

[OAuth2] and [Json Web Token] implementation for adding authentication
and the like to [Rocket] applications.

## usage example

The below code accepts OAuth2 requests and always grants `resource_owner`
requests. It also includes an example scope that can be used to restrict
access to routes.

See [readme.rs](examples/readme.rs) for a more complete and documented example.

```rust
/* use <...> */

const_str! {
    type HasTest = "test";
}

#[rocket::launch]
pub fn launch() -> _ {
    let provider = TestProvider { hs256: HS256::new(SecretStr::new("secret")) };
    rocket::build()
        .attach(rocket_identity::fairing(provider, "/"))
        .mount("/", routes![test])
}

#[rocket::get("/test")]
fn test(auth: Bearer![TestRole, HasTest]) -> String {
    let sub = auth.role.claims.subject.as_deref().unwrap();
    format!("Hello, {sub}!")
}

pub struct TestProvider {
    hs256: HS256,
}

impl Provider for TestProvider {
    type ClientError = Error;

    fn make_responder<'r>(&self, error: Self::ClientError) -> impl Responder<'r, 'static> {
        Json(error)
    }

    fn get_verifier<R: Role<Provider = Self>>(
        &'_ self,
        alg: JwtAlgorithm,
        header: &JwtHeader,
    ) -> Result<RefOrOwned<'_, dyn VerifyToken<R> + Send + Sync>, TokenVerifyError<R>> {
        match alg {
            JwtAlgorithm::HS256 => Ok(Ref(&self.hs256)),
            other => Err(TokenVerifyError::UnsupportedAlgorithm(other)),
        }
    }

    provider_routes! {
        use Self::oauth2();
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

// required by [Role] for logging purposes!
impl Display for TestRole { /* ... */ }

#[async_trait]
impl Role for TestRole {
    type Provider = TestProvider;
    type Scope = HashSet<String>;
    type ValidationError = Infallible;
    type ClaimsExtra = RoleExtra;

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
                    .expiration(Utc::now() + Duration::minutes(15))
                    .issued_at(Utc::now())
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

impl Display for Error { /* ... */ }

impl std::error::Error for Error {}

impl From<GeneralError> for Error {
    fn from(e: GeneralError) -> Self {
        Error::General(e)
    }
}
```

[OAuth2]: https://www.rfc-editor.org/rfc/rfc6749
[Json Web Token]: https://datatracker.ietf.org/doc/html/rfc7519
[Rocket]: https://rocket.rs/
