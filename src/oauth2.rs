use crate::secret::{AuthorizationHeader, SecretStr};
use crate::tokens::TokenSignError;
use crate::{GeneralError, JwkContent, JwkSet, Provider, Role};
use chrono::{DateTime, Utc};
use rocket::data::FromData;
use rocket::form::{DataField, Error, Errors, Form, FromForm, Options, ValueField};
use rocket::http::uri::Absolute;
use rocket::http::{ContentType, Status};
use rocket::outcome::Outcome;
use rocket::request::FromRequest;
use rocket::response::Responder;
use rocket::serde::json::Json;
use rocket::serde::{Deserialize, Serialize};
use rocket::{async_trait, route, Data, Request, Response};
use std::borrow::Cow;
use std::collections::HashSet;
use std::io::Cursor;
use std::mem;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

/// Implements the `error` field as described by the OAuth2 spec.
///
/// <https://www.rfc-editor.org/rfc/rfc6749#section-5.2>
#[derive(Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum Oauth2Error<'r> {
    /// > The request is missing a required parameter, includes an
    /// > unsupported parameter value (other than grant type),
    /// > repeats a parameter, includes multiple credentials,
    /// > utilizes more than one mechanism for authenticating the
    /// > client, or is otherwise malformed.
    InvalidRequest {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error_description: Option<String>,

        #[serde(default, skip_serializing_if = "Option::is_none")]
        error_uri: Option<String>
    },

    /// > Client authentication failed (e.g., unknown client, no
    /// > client authentication included, or unsupported
    /// > authentication method).  The authorization server MAY
    /// > return an HTTP 401 (Unauthorized) status code to indicate
    /// > which HTTP authentication schemes are supported.  If the
    /// > client attempted to authenticate via the "Authorization"
    /// > request header field, the authorization server MUST
    /// > respond with an HTTP 401 (Unauthorized) status code and
    /// > include the "WWW-Authenticate" response header field
    /// > matching the authentication scheme used by the client.
    InvalidClient {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error_description: Option<String>,

        #[serde(default, skip_serializing_if = "Option::is_none")]
        error_uri: Option<String>
    },

    /// > The provided authorization grant (e.g., authorization
    /// > code, resource owner credentials) or refresh token is
    /// > invalid, expired, revoked, does not match the redirection
    /// > URI used in the authorization request, or was issued to
    /// > another client.
    InvalidGrant {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error_description: Option<String>,

        #[serde(default, skip_serializing_if = "Option::is_none")]
        error_uri: Option<String>
    },

    /// > The authenticated client is not authorized to use this
    /// > authorization grant type.
    UnauthorizedClient {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error_description: Option<String>,

        #[serde(default, skip_serializing_if = "Option::is_none")]
        error_uri: Option<String>
    },

    /// > The authorization grant type is not supported by the
    /// > authorization server.
    UnsupportedGrantType {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error_description: Option<String>,

        #[serde(default, skip_serializing_if = "Option::is_none")]
        error_uri: Option<String>,

        grant_type: Cow<'r, str>
    },

    /// > The requested scope is invalid, unknown, malformed, or
    /// > exceeds the scope granted by the resource owner.
    InvalidScope {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error_description: Option<String>,

        #[serde(default, skip_serializing_if = "Option::is_none")]
        error_uri: Option<String>,

        scope: Cow<'r, str>
    },
}

impl<R: Role> From<crate::tokens::TokenSignError<R>> for Oauth2Error<'static> {
    fn from(value: TokenSignError<R>) -> Self {
        match value {
            TokenSignError::Validation(e) => Oauth2Error::UnauthorizedClient {
                error_description: Some(e.to_string()),
                error_uri: None,
            },
            TokenSignError::Serialization(_) => Oauth2Error::InvalidRequest {
                error_description: Some("serialization error".into()),
                error_uri: None,
            },
            TokenSignError::Base64(e) => Oauth2Error::InvalidRequest {
                error_description: Some(e.to_string()),
                error_uri: None,
            }
        }
    }
}

#[derive(Default)]
#[doc(hidden)]
pub struct Oauth2TokenBuildContext<'r> {
    form: Oauth2TokenForm<'r>,
    errors: Errors<'r>,
    strict: bool,
}

impl<'r> Oauth2TokenBuildContext<'r> {
    pub fn then_error(&mut self, error: Error<'r>) {
        if self.strict {
            self.form = Oauth2TokenForm::Errored(Oauth2Error::InvalidRequest {
                error_description: Some(error.to_string()),
                error_uri: None
            })
        }

        self.errors.push(error);
    }
}

pub enum Oauth2TokenForm<'r> {
    Init(Vec<ValueField<'r>>),
    Errored(Oauth2Error<'r>),

    AuthorizationCode {
        code: &'r SecretStr,
        redirect_uri: Option<Absolute<'r>>,
        client_id: Option<&'r str>,
    },

    ResourceOwnerPassword {
        username: &'r str,
        password: &'r SecretStr,
        scope: Option<Box<HashSet<&'r str>>>,
    },

    ClientCredentials {
        client_id: Option<&'r str>,
        client_secret: Option<&'r SecretStr>,
        scope: Option<Box<HashSet<&'r str>>>,
    }
}

impl Default for Oauth2TokenForm<'_> {
    fn default() -> Self {
        Self::Init(Vec::new())
    }
}

#[async_trait]
impl<'r> FromForm<'r> for Oauth2TokenForm<'r> {
    type Context = Oauth2TokenBuildContext<'r>;

    fn init(opts: Options) -> Self::Context {
        Oauth2TokenBuildContext {
            strict: opts.strict,
            ..Default::default()
        }
    }

    fn push_value(ctxt: &mut Self::Context, field: ValueField<'r>) {
        let key = match field.name.key() {
            Some(key) => key,
            None => {
                ctxt.errors.push(Error::validation("invalid key"));
                return;
            }
        };

        match &mut ctxt.form {
            Oauth2TokenForm::Init(params) => {
                match key.as_str() {
                    "grant_type" => {
                        let v = mem::replace(&mut ctxt.form, match field.value {
                            "authorization_code" => Oauth2TokenForm::AuthorizationCode {
                                code: SecretStr::new(""),
                                redirect_uri: None,
                                client_id: None,
                            },
                            "password" => Oauth2TokenForm::ResourceOwnerPassword {
                                username: "",
                                password: SecretStr::new(""),
                                scope: None,
                            },
                            "client_credentials" => Oauth2TokenForm::ClientCredentials {
                                client_id: None,
                                client_secret: None,
                                scope: None,
                            },
                            other => {
                                ctxt.errors.push(Error::validation(format!("invalid grant type: {other}")));
                                ctxt.form = Oauth2TokenForm::Errored(Oauth2Error::UnsupportedGrantType {
                                    error_description: None,
                                    error_uri: None,
                                    grant_type: other.into()
                                });
                                return;
                            }
                        });

                        if let Oauth2TokenForm::Init(params) = v {
                            for param in params {
                                Self::push_value(ctxt, param);
                            }
                        }
                    }
                    _ => params.push(field),
                }
            }
            Oauth2TokenForm::Errored(_) => return,

            Oauth2TokenForm::AuthorizationCode {
                code,
                redirect_uri,
                client_id
            } => match key.as_str() {
                "code" => *code = SecretStr::new(field.value),
                "redirect_uri" => *redirect_uri = Some(match Absolute::parse(field.value) {
                    Ok(uri) => uri,
                    Err(e) => return ctxt.errors.push(Error::validation(format!("error parsing uri {}: {e}", field.value)))
                }),
                "client_id" => *client_id = Some(field.value),
                _ => ctxt.then_error(field.unexpected()),
            }

            Oauth2TokenForm::ResourceOwnerPassword {
                username,
                password,
                scope
            } => match key.as_str() {
                "username" => *username = field.value,
                "password" => *password = SecretStr::new(field.value),
                "scope" => *scope = Some(Box::new(HashSet::from_iter(field.value.split_whitespace().filter(|s| !s.is_empty())))),
                _ => ctxt.then_error(field.unexpected()),
            }

            Oauth2TokenForm::ClientCredentials {
                client_id,
                client_secret,
                scope
            } => match key.as_str() {
                "client_id" => *client_id = Some(field.value),
                "client_secret" => *client_secret = Some(SecretStr::new(field.value)),
                "scope" => *scope = Some(Box::new(HashSet::from_iter(field.value.split_whitespace().filter(|s| !s.is_empty())))),
                _ => ctxt.then_error(field.unexpected()),
            }
        }
    }

    async fn push_data(ctxt: &mut Self::Context, field: DataField<'r, '_>) {
        ctxt.then_error(field.unexpected());
    }

    fn finalize(ctxt: Self::Context) -> rocket::form::Result<'r, Self> {
        Ok(match ctxt.form {
            Oauth2TokenForm::Init(_) => Oauth2TokenForm::Errored(Oauth2Error::InvalidRequest {
                error_description: None,
                error_uri: None,
            }),
            other => other
        })
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Oauth2Response<Extra = ()> {
    pub access_token: Box<SecretStr>,
    pub token_type: Cow<'static, str>,
    pub expires_in: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<Box<SecretStr>>,
    #[serde(flatten)]
    extra: Extra
}

impl Oauth2Response<()> {
    pub fn new(
        access_token: impl Into<Box<SecretStr>>,
        token_type: impl Into<Cow<'static, str>>,
        expires: DateTime<Utc>
    ) -> Self {
        Self {
            access_token: access_token.into(),
            token_type: token_type.into(),
            expires_in: (expires - Utc::now()).num_seconds() as u64,
            refresh_token: None,
            extra: ()
        }
    }
}

impl<Extra> Oauth2Response<Extra> {
    pub fn new_with(
        access_token: impl Into<Box<SecretStr>>,
        token_type: impl Into<Cow<'static, str>>,
        expires: DateTime<Utc>,
        extra: Extra
    ) -> Self {
        Self {
            access_token: access_token.into(),
            token_type: token_type.into(),
            expires_in: (expires - Utc::now()).num_seconds() as u64,
            refresh_token: None,
            extra
        }
    }

    pub fn with_refresh_token(self, token: impl Into<Box<SecretStr>>) -> Self {
        Self {
            refresh_token: Some(token.into()),
            ..self
        }
    }
}

impl<Extra> Deref for Oauth2Response<Extra> {
    type Target = Extra;

    fn deref(&self) -> &Self::Target {
        &self.extra
    }
}

impl<Extra> DerefMut for Oauth2Response<Extra> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.extra
    }
}

pub fn oauth2_token<'r, V: Provider + Oauth2 + Send + Sync + 'static>(
    request: &'r Request,
    data: Data<'r>
) -> route::BoxFuture<'r> {
    Box::pin(async move {
        let provider: &Arc<V> = request.rocket().state().unwrap();
        let authorization = AuthorizationHeader::from_request(request).await.succeeded()
            .and_then(|v| {
                match v {
                    AuthorizationHeader::Basic {
                        username,
                        password
                    } => Some((username, password)),
                    _ => None
                }
            });

        let form = if let Some(ty) = request.content_type() && ty.is_form() {
            match Form::<Oauth2TokenForm<'r>>::from_data(request, data).await {
                Outcome::Success(form) => form.into_inner(),
                Outcome::Error((status, _)) => return Outcome::Error(status),
                Outcome::Forward((data, status)) => return Outcome::Forward((data, status)),
            }
        } else {
            match Form::<Oauth2TokenForm<'r>>::parse_iter(request.query_fields()) {
                Ok(form) => form,
                Err(e) => {
                    let error = Oauth2Error::InvalidRequest {
                        error_description: Some(e.to_string()),
                        error_uri: None
                    };

                    return Outcome::Success(make_error(&error));
                }
            }
        };

        let client_id = authorization.as_ref().map(|v| v.0.as_ref());
        let client_secret = authorization.as_ref().map(|v| v.1.as_ref());

        let res = match form {
            Oauth2TokenForm::Init(_) => unreachable!(),
            Oauth2TokenForm::Errored(e) => Err(e),
            Oauth2TokenForm::AuthorizationCode {
                code,
                client_id: form_client_id,
                redirect_uri
            } => {
                let client_id = client_id.or(form_client_id);

                if let Some(client_id) = client_id {
                    provider.token_from_authorization_code(
                        client_id,
                        client_secret,
                        code,
                        redirect_uri
                    ).await
                } else {
                    Err(Oauth2Error::UnauthorizedClient {
                        error_description: None,
                        error_uri: None
                    })
                }
            }
            Oauth2TokenForm::ResourceOwnerPassword {
                username,
                password,
                scope
            } => {
                if let (Some(client_id), Some(client_secret)) = (client_id, client_secret) {
                    let scope: Vec<&str> = scope.unwrap_or_default().into_iter().collect();
                    provider.token_from_resource_owner_password(
                        client_id,
                        client_secret,
                        username,
                        password,
                        scope.as_slice()
                    ).await
                } else {
                    Err(Oauth2Error::UnauthorizedClient {
                        error_description: Some("no authorization provided".into()),
                        error_uri: None
                    })
                }
            }
            Oauth2TokenForm::ClientCredentials {
                client_id: form_client_id,
                client_secret: form_client_secret,
                scope
            } => {
                let client_id = client_id.or(form_client_id);
                let client_secret = client_secret.or(form_client_secret);

                if let (Some(client_id), Some(client_secret)) = (client_id, client_secret) {
                    let scope: Vec<&str> = scope.unwrap_or_default().into_iter().collect();
                    provider.token_from_client_credentials(
                        client_id,
                        client_secret,
                        scope.as_slice()
                    ).await
                } else {
                    Err(Oauth2Error::UnauthorizedClient {
                        error_description: Some("no authorization provided".into()),
                        error_uri: None
                    })
                }
            }
        };

        Outcome::Success(match res {
            Ok(value) => Response::build()
                .status(Status::Ok)
                .header(ContentType::JSON)
                .sized_body(None, json_body(&value))
                .finalize(),
            Err(e) => make_error(&e)
        })
    })
}

#[derive(FromForm)]
pub struct Oauth2RevokeForm<'r> {
    pub client_id: Option<&'r str>,
    pub client_secret: Option<&'r SecretStr>,
    pub token_type_hint: Option<&'r str>,
    pub token: &'r SecretStr
}

pub fn oauth2_revoke<'r, V: Provider + Oauth2 + Send + Sync + 'static>(
    request: &'r Request,
    data: Data<'r>
) -> route::BoxFuture<'r> {
    Box::pin(async move {
        let provider: &Arc<V> = request.rocket().state().unwrap();
        let authorization = AuthorizationHeader::from_request(request).await.succeeded()
            .and_then(|v| {
                match v {
                    AuthorizationHeader::Basic {
                        username,
                        password
                    } => Some((username, password)),
                    _ => None
                }
            });

        let form = if let Some(ty) = request.content_type() && ty.is_form() {
            match Form::<Oauth2RevokeForm<'r>>::from_data(request, data).await {
                Outcome::Success(form) => form.into_inner(),
                Outcome::Error((status, _)) => return Outcome::Error(status),
                Outcome::Forward((data, status)) => return Outcome::Forward((data, status)),
            }
        } else {
            match Form::<Oauth2RevokeForm<'r>>::parse_iter(request.query_fields()) {
                Ok(form) => form,
                Err(e) => {
                    let error = Oauth2Error::InvalidRequest {
                        error_description: Some(e.to_string()),
                        error_uri: None
                    };

                    return Outcome::Success(make_error(&error));
                }
            }
        };

        let client_id = authorization.as_ref().map(|v| v.0.as_ref()).or(form.client_id);
        let client_secret = authorization.as_ref().map(|v| v.1.as_ref()).or(form.client_secret);

        let res = if let Some(client_id) = client_id {
            provider.revoke_token(client_id, client_secret, form.token_type_hint, form.token).await
        } else {
            Err(GeneralError::NotAuthorized.into())
        };

        Outcome::Success(match res {
            Ok(value) => Response::build()
                .status(Status::Ok)
                .header(ContentType::JSON)
                .sized_body(None, json_body(&value))
                .finalize(),
            Err(e) => match provider.make_responder(e).respond_to(request) {
                Ok(resp) => resp,
                Err(e) => return Outcome::Error(e)
            }
        })
    })
}

fn make_error<'o>(error: &Oauth2Error) -> Response<'o> {
    Response::build()
        .status(match error {
            Oauth2Error::UnauthorizedClient { .. } => Status::Unauthorized,
            _ => Status::BadRequest
        })
        .header(ContentType::JSON)
        .sized_body(None, json_body(error))
        .finalize()
}

fn json_body(error: &impl Serialize) -> Cursor<Vec<u8>> {
    Cursor::new(match serde_json::to_string(error) {
        Ok(json) => json.into_bytes(),
        Err(_) => Vec::<u8>::new()
    })
}

#[async_trait]
#[allow(unused)]
pub trait Oauth2: Provider {
    type ExtraResponse: Serialize;

    async fn generate_authorization_code(
        &self,
        client_id: &str,
        redirect_uri: Option<&str>,
        scopes: &[&str],
        state: Option<&str>,
    ) -> Result<Box<SecretStr>, Self::ClientError> {
        Err(GeneralError::NotImplemented.into())
    }

    async fn token_from_authorization_code(
        &self,
        client_id: &str,
        client_secret: Option<&SecretStr>,
        code: &SecretStr,
        redirect_uri: Option<Absolute<'_>>,
    ) -> Result<Oauth2Response<Self::ExtraResponse>, Oauth2Error> {
        Err(Oauth2Error::UnsupportedGrantType {
            error_description: None,
            error_uri: None,
            grant_type: "authorization_code".into()
        })
    }

    async fn token_from_resource_owner_password(
        &self,
        client_id: &str,
        client_secret: &SecretStr,
        username: &str,
        password: &SecretStr,
        scopes: &[&str],
    ) -> Result<Oauth2Response<Self::ExtraResponse>, Oauth2Error> {
        Err(Oauth2Error::UnsupportedGrantType {
            error_description: None,
            error_uri: None,
            grant_type: "password".into()
        })
    }

    async fn token_from_client_credentials(
        &self,
        client_id: &str,
        client_secret: &SecretStr,
        scopes: &[&str],
    ) -> Result<Oauth2Response<Self::ExtraResponse>, Oauth2Error> {
        Err(Oauth2Error::UnsupportedGrantType {
            error_description: None,
            error_uri: None,
            grant_type: "client_credentials".into()
        })
    }

    async fn revoke_token(
        &self,
        client_id: &str,
        client_secret: Option<&SecretStr>,
        token_hint: Option<&str>,
        token: &SecretStr,
    ) -> Result<(), Self::ClientError> {
        Err(GeneralError::NotImplemented.into())
    }
}

pub trait KeySet: Provider {
    fn get_key_set(&self) -> impl IntoIterator<Item = JwkContent>;
}

pub fn jwk_key_set<'r, V: Provider + KeySet + Send + Sync + 'static>(
    request: &'r Request,
    _: Data<'r>
) -> route::BoxFuture<'r> {
    Box::pin(async move {
        let provider = request.rocket().state::<Arc<V>>().unwrap();
        let res = Json(JwkSet {
            keys: provider.get_key_set().into_iter().collect()
        }).respond_to(request);
        match res {
            Ok(resp) => Outcome::Success(resp),
            Err(e) => Outcome::Error(e)
        }
    })
}
