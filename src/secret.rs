use std::fmt::{Debug, Display, Formatter};
use std::mem;
use base64ct::{Base64, Decoder, Encoder};
use ref_cast::RefCast;
use rocket::{async_trait, Request};
use rocket::form::{FromFormField, ValueField};
use rocket::http::{Header, Status};
use rocket::http::uri::fmt::{FromUriParam, Part, UriDisplay};
use rocket::request::{FromRequest, Outcome};
use rocket::serde::{Deserializer, Serializer};
use rocket::serde::de::Error;
use serde::{Deserialize, Serialize};
use serde::de::Visitor;

#[derive(RefCast, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct SecretStr(str);

impl Debug for SecretStr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("<token>")
    }
}

impl SecretStr {
    pub fn new(s: &str) -> &Self {
        Self::ref_cast(s)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
    
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn expose(&self) -> impl Display + Debug + Copy + Clone + '_ {
        &self.0
    }

    pub fn expose_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn split_once(&self, c: char) -> Option<(&Self, &Self)> {
        self.0.split_once(c).map(|(a, b)| (Self::ref_cast(a), Self::ref_cast(b)))
    }

    pub fn rsplit_once(&self, c: char) -> Option<(&Self, &Self)> {
        self.0.rsplit_once(c).map(|(a, b)| (Self::ref_cast(a), Self::ref_cast(b)))
    }
}

impl From<&SecretStr> for Box<SecretStr> {
    fn from(value: &SecretStr) -> Self {
        let b = Box::<str>::from(&value.0);
        b.into()
    }
}

impl From<&str> for Box<SecretStr> {
    fn from(value: &str) -> Self {
        Box::from(SecretStr::new(value))
    }
}

impl From<String> for Box<SecretStr> {
    fn from(value: String) -> Self {
        Box::from(SecretStr::new(value.as_str()))
    }
}

impl From<Box<str>> for Box<SecretStr> {
    fn from(value: Box<str>) -> Self {
        unsafe { mem::transmute(value) }
    }
}

impl Serialize for SecretStr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer
    {
        serializer.serialize_str(&self.0)
    }
}

struct TokenVisitor;

impl<'de> Visitor<'de> for TokenVisitor {
    type Value = &'de SecretStr;

    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
        formatter.write_str("a borrowed string representing a token")
    }

    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(SecretStr::new(v))
    }
}

impl<'de> Deserialize<'de> for &'de SecretStr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>
    {
        deserializer.deserialize_str(TokenVisitor)
    }
}

impl<'de> Deserialize<'de> for Box<SecretStr> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>
    {
        deserializer.deserialize_str(TokenVisitor).map(Box::from)
    }
}

impl PartialEq<str> for SecretStr {
    fn eq(&self, other: &str) -> bool {
        &self.0 == other
    }
}

impl PartialEq<SecretStr> for str {
    fn eq(&self, other: &SecretStr) -> bool {
        other == self
    }
}

pub enum AuthorizationHeader<'r> {
    Basic { username: Box<str>, password: Box<SecretStr> },
    Bearer { token: &'r SecretStr },
    Custom { name: &'r str, token: &'r SecretStr },
}

impl<'r> From<AuthorizationHeader<'r>> for Header<'r> {
    fn from(value: AuthorizationHeader<'r>) -> Self {
        Self::new("authorization", match value {
            AuthorizationHeader::Basic { username, password } => {
                let mut bytes = vec![0u8; (username.len() + password.len() + 1) * 2];
                let mut enc = Encoder::<Base64>::new(&mut bytes).unwrap();
                enc.encode(format!("{username}:{}", password.expose()).as_bytes()).unwrap();
                format!("Basic {}", enc.finish().unwrap())
            }
            AuthorizationHeader::Bearer { token } => format!("Bearer {}", token.expose()),
            AuthorizationHeader::Custom { name, token } => format!("{} {}", name, token.expose()),
        })
    }
}

#[async_trait]
impl<'r> FromRequest<'r> for AuthorizationHeader<'r> {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match request.headers().get_one("Authorization").and_then(|v| v.split_once(' ')) {
            None => Outcome::Forward(Status::Unauthorized),
            Some(("Basic", auth)) => {
                let mut vec = Vec::<u8>::new();
                match Decoder::<Base64>::new(auth.as_bytes()).and_then(|mut v| v.decode_to_end(&mut vec)) {
                    Ok(_) => match String::from_utf8(vec) {
                        Ok(value) => match value.split_once(':') {
                            Some((username, password)) => {
                                Outcome::Success(AuthorizationHeader::Basic {
                                    username: username.into(),
                                    password: password.into(),
                                })
                            }
                            None => Outcome::Forward(Status::Unauthorized),
                        },
                        Err(_) => Outcome::Forward(Status::Unauthorized),
                    },
                    Err(_) => Outcome::Forward(Status::Unauthorized),
                }
            }
            Some(("Bearer", token)) => Outcome::Success(AuthorizationHeader::Bearer {
                token: SecretStr::new(token)
            }),
            Some((name, token)) => Outcome::Success(AuthorizationHeader::Custom {
                name,
                token: SecretStr::new(token)
            }),
        }
    }
}

impl Clone for Box<SecretStr> {
    fn clone(&self) -> Self {
        Box::from(&**self)
    }
}

impl<'r, P: Part> FromUriParam<P, &'r SecretStr> for &'r SecretStr {
    type Target = &'r SecretStr;

    fn from_uri_param(param: &'r SecretStr) -> Self::Target {
        param
    }
}

impl<'r, P: Part> UriDisplay<P> for SecretStr {
    fn fmt(&self, f: &mut rocket::http::uri::fmt::Formatter<'_, P>) -> std::fmt::Result {
        f.write_value(&self.0)
    }
}

impl<'r> FromFormField<'r> for &'r SecretStr {
    fn from_value(field: ValueField<'r>) -> rocket::form::Result<'r, Self> {
        Ok(SecretStr::new(field.value))
    }
}
