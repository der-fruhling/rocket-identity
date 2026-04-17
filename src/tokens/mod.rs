mod ecdsa_alg;
mod hmac_alg;
mod rsassa_pkcs1_v15_alg;
mod rsassa_pss_alg;

use crate::secret::SecretStr;
use crate::{JwtAlgorithm, JwtClaims, JwtHeader, RefOrOwned, Role};
use base64ct::{Base64UrlUnpadded, Decoder, Encoder};
use chrono::{DateTime, Utc};
use rocket::async_trait;
use std::fmt::Debug;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TokenSignError<R: Role> {
    #[error("from role: {0}")]
    Validation(R::ValidationError),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("base64 error: {0}")]
    Base64(#[from] base64ct::Error),
}

#[derive(Error, Debug)]
pub enum TokenVerifyError<R: Role> {
    #[error("from role: {0}")]
    Validation(R::ValidationError),

    #[error("not a JWT")]
    NotJWT,

    #[error("unparsable input")]
    UnparsableInput,

    #[error("signature check failed")]
    SignatureCheckFailed,

    #[error("expired {expires} (currently {now})")]
    Expired {
        now: DateTime<Utc>,
        expires: DateTime<Utc>,
    },

    #[error("cannot be used before {not_before} (currently {now})")]
    NotBefore {
        now: DateTime<Utc>,
        not_before: DateTime<Utc>,
    },

    #[error("unsupported algorithm: {0:?}")]
    UnsupportedAlgorithm(JwtAlgorithm),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("base64 error: {0}")]
    Base64(#[from] base64ct::Error),

    #[error("missing scopes: {0}")]
    MissingScopes(String),
}

pub struct TokenSignResult {
    pub token: Box<SecretStr>,
    pub expires: DateTime<Utc>,
}

#[async_trait]
pub trait SignToken<R: Role> {
    async fn sign_token(&self, role: R, header: Option<JwtHeader<R::HeaderExtra>>) -> Result<TokenSignResult, TokenSignError<R>>;
}

#[async_trait]
pub trait VerifyToken<R: Role> {
    async fn verify_token(
        &self,
        provider: &R::Provider,
        token: &SecretStr,
    ) -> Result<R, TokenVerifyError<R>>;
}

pub struct Unsigned {
    header: Box<str>,
}

impl Unsigned {
    pub fn new() -> Self {
        let mut bytes = [0u8; 38];
        let mut enc = Encoder::<Base64UrlUnpadded>::new(&mut bytes).unwrap();

        enc.encode(
            &serde_json::to_vec(&JwtHeader::<()> {
                alg: JwtAlgorithm::None,
                ..Default::default()
            })
            .unwrap(),
        )
        .unwrap();

        Self {
            header: enc.finish().unwrap().into(),
        }
    }
}

#[async_trait]
impl<R: Role> SignToken<R> for Unsigned {
    async fn sign_token(&self, role: R, header: Option<JwtHeader<R::HeaderExtra>>) -> Result<TokenSignResult, TokenSignError<R>> {
        let claims = role.into_claims().map_err(TokenSignError::Validation)?;
        let body = serde_json::to_vec(&claims)?;
        let mut b64 = vec![0u8; body.len() * 2];
        let mut enc = Encoder::<Base64UrlUnpadded>::new(&mut b64)?;
        enc.encode(&body)?;
        let signable = format!("{}.{}.", self.header, enc.finish()?);

        Ok(TokenSignResult {
            token: signable.into(),
            expires: claims.expires.unwrap_or(DateTime::<Utc>::MAX_UTC),
        })
    }
}

#[async_trait]
impl<R: Role> SignToken<R> for RefOrOwned<'_, dyn SignToken<R> + Send + Sync> {
    async fn sign_token(&self, role: R, header: Option<JwtHeader<R::HeaderExtra>>) -> Result<TokenSignResult, TokenSignError<R>> {
        self.as_ref().sign_token(role, header).await
    }
}

#[async_trait]
impl<R: Role> VerifyToken<R> for Unsigned {
    async fn verify_token(
        &self,
        provider: &R::Provider,
        token: &SecretStr,
    ) -> Result<R, TokenVerifyError<R>> {
        let (content, signature) = token
            .rsplit_once('.')
            .ok_or(TokenVerifyError::UnparsableInput)?;

        if !signature.is_empty() {
            return Err(TokenVerifyError::UnparsableInput);
        };

        let (_header, content) = content
            .split_once('.')
            .ok_or(TokenVerifyError::UnparsableInput)?;
        let mut bytes = Vec::<u8>::new();
        Decoder::<Base64UrlUnpadded>::new(content.expose_bytes())?.decode_to_end(&mut bytes)?;
        let role: JwtClaims<R::ClaimsExtra> = serde_json::from_slice(&bytes)?;

        let now = Utc::now();
        if let Some(expires) = role.expires
            && expires < now
        {
            return Err(TokenVerifyError::Expired { now, expires });
        }

        if let Some(not_before) = role.not_before.or(role.issued_at)
            && not_before > now
        {
            return Err(TokenVerifyError::NotBefore { now, not_before });
        }

        Ok(R::from_claims(provider, role)
            .await
            .map_err(TokenVerifyError::Validation)?)
    }
}

#[async_trait]
impl<R: Role> VerifyToken<R> for RefOrOwned<'_, dyn VerifyToken<R> + Send + Sync> {
    async fn verify_token(
        &self,
        provider: &R::Provider,
        token: &SecretStr,
    ) -> Result<R, TokenVerifyError<R>> {
        self.as_ref().verify_token(provider, token).await
    }
}

pub struct PublicKey;
pub struct PrivateKey;

#[cfg(feature = "es256")]
pub use ecdsa_alg::ES256;
#[cfg(feature = "es384")]
pub use ecdsa_alg::ES384;
#[cfg(feature = "es512")]
pub use ecdsa_alg::ES512;
#[cfg(feature = "hs256")]
pub use hmac_alg::HS256;
#[cfg(feature = "hs384")]
pub use hmac_alg::HS384;
#[cfg(feature = "hs512")]
pub use hmac_alg::HS512;
#[cfg(feature = "rs256")]
pub use rsassa_pkcs1_v15_alg::RS256;
#[cfg(feature = "rs384")]
pub use rsassa_pkcs1_v15_alg::RS384;
#[cfg(feature = "rs512")]
pub use rsassa_pkcs1_v15_alg::RS512;
#[cfg(feature = "ps256")]
pub use rsassa_pss_alg::PS256;
#[cfg(feature = "ps384")]
pub use rsassa_pss_alg::PS384;
#[cfg(feature = "ps512")]
pub use rsassa_pss_alg::PS512;

#[macro_export(local_inner_macros)]
macro_rules! jwk_tests {
    ($type:ty, $TestProvider:ident, $TestRole:ident => $item:expr) => {
        #[test]
        fn snag_key() {
            let key: crate::JwkContent = $item.as_key();

            std::assert!(key.alg.is_some());
            std::assert_eq!(key.key_ops, std::vec![crate::JwkKeyOp::Verify]);

            match key.key {
                JwkKey::EC { d, .. } => std::assert!(d.is_none()),
                JwkKey::RSA { private_key, .. } => std::assert!(private_key.is_none()),
                JwkKey::Oct { .. } => std::panic!("oct unsupported"),
            }
        }

        #[test]
        fn snag_private_key() {
            #[allow(deprecated)]
            let key: crate::JwkContent = $item.as_private_key_exposed();

            std::assert!(key.alg.is_some());
            std::assert_eq!(
                key.key_ops,
                std::vec![crate::JwkKeyOp::Verify, crate::JwkKeyOp::Sign]
            );

            match key.key {
                JwkKey::EC { d, .. } => std::assert!(d.is_some()),
                JwkKey::RSA { private_key, .. } => {
                    std::assert!(private_key.is_some_and(|p| { p.oth.is_empty() }))
                }
                JwkKey::Oct { .. } => std::panic!("oct unsupported"),
            }
        }
    };
}

#[macro_export(local_inner_macros)]
macro_rules! define_tests {
    ($type:ty$(; $($extra:ident),* $(,)?)?) => {
        use super::*;

        use std::prelude::rust_2024::*;
        use std::sync::LazyLock;
        use crate::{JwtClaims};
        use crate::tokens::{SignToken, VerifyToken, TokenVerifyError};
        use crate::tokens::test_common::{TestProvider, TestRole};

        static __ITEM: LazyLock<$type> = LazyLock::new(|| <$type>::test_item());

        #[test]
        fn sign_token() {
            let role = TestRole(JwtClaims::new()
                .subject("Test")
                .build());
            let token = ::pollster::block_on(
                <$type as SignToken<TestRole>>::sign_token(&__ITEM, role.clone(), None)
            ).unwrap();

            let new = ::pollster::block_on(
                __ITEM.verify_token(&TestProvider, token.token.as_ref())
            ).unwrap();

            ::std::assert_eq!(role, new);
        }

        #[test]
        fn check_token_expiry() {
            let role = TestRole(JwtClaims::new()
                .subject("Test")
                .expiration(::chrono::Utc::now() - ::chrono::Duration::seconds(60))
                .build());
            let token = ::pollster::block_on(
                <$type as SignToken<TestRole>>::sign_token(&__ITEM, role.clone(), None)
            ).unwrap();

            let res = ::pollster::block_on(
                <$type as VerifyToken<TestRole>>::verify_token(&__ITEM, &TestProvider, token.token.as_ref())
            );

            std::assert!(std::matches!(res, Err(TokenVerifyError::Expired { .. })));
        }

        #[test]
        fn check_token_not_before() {
            let role = TestRole(JwtClaims::new()
                .subject("Test")
                .not_before(::chrono::Utc::now() + ::chrono::Duration::seconds(60))
                .build());
            let token = ::pollster::block_on(
                <$type as SignToken<TestRole>>::sign_token(&__ITEM, role.clone(), None)
            ).unwrap();

            let res = ::pollster::block_on(
                <$type as VerifyToken<TestRole>>::verify_token(&__ITEM, &TestProvider, token.token.as_ref())
            );

            std::assert!(std::matches!(res, Err(TokenVerifyError::NotBefore { .. })));
        }

        #[test]
        fn check_token_issued_at() {
            let role = TestRole(JwtClaims::new()
                .subject("Test")
                .issued_at(::chrono::Utc::now() + ::chrono::Duration::seconds(60))
                .build());
            let token = ::pollster::block_on(
                <$type as SignToken<TestRole>>::sign_token(&__ITEM, role.clone(), None)
            ).unwrap();

            let res = ::pollster::block_on(
                <$type as VerifyToken<TestRole>>::verify_token(&__ITEM, &TestProvider, token.token.as_ref())
            );

            std::assert!(std::matches!(res, Err(TokenVerifyError::NotBefore { .. })));
        }

        #[test]
        fn check_token_expiry_issued_at_precedence() {
            let role = TestRole(JwtClaims::new()
                .subject("Test")
                .expiration(::chrono::Utc::now() - ::chrono::Duration::seconds(60))
                .issued_at(::chrono::Utc::now() + ::chrono::Duration::seconds(60))
                .build());
            let token = ::pollster::block_on(
                <$type as SignToken<TestRole>>::sign_token(&__ITEM, role.clone(), None)
            ).unwrap();

            let res = ::pollster::block_on(
                <$type as VerifyToken<TestRole>>::verify_token(&__ITEM, &TestProvider, token.token.as_ref())
            );

            std::assert!(std::matches!(res, Err(TokenVerifyError::Expired { .. })));
        }

        #[test]
        fn check_token_not_before_issued_at_precedence() {
            let role = TestRole(JwtClaims::new()
                .subject("Test")
                .not_before(::chrono::Utc::now() - ::chrono::Duration::seconds(60))
                .issued_at(::chrono::Utc::now() + ::chrono::Duration::seconds(60))
                .build());
            let token = ::pollster::block_on(
                <$type as SignToken<TestRole>>::sign_token(&__ITEM, role.clone(), None)
            ).unwrap();

            let res = ::pollster::block_on(
                <$type as VerifyToken<TestRole>>::verify_token(&__ITEM, &TestProvider, token.token.as_ref())
            );

            std::assert!(std::matches!(res, Ok(..)));
        }

        #[test]
        fn check_token_not_before_issued_at_precedence_fail() {
            let role = TestRole(JwtClaims::new()
                .subject("Test")
                .not_before(::chrono::Utc::now() + ::chrono::Duration::seconds(60))
                .issued_at(::chrono::Utc::now() - ::chrono::Duration::seconds(60))
                .build());
            let token = ::pollster::block_on(
                <$type as SignToken<TestRole>>::sign_token(&__ITEM, role.clone(), None)
            ).unwrap();

            let res = ::pollster::block_on(
                <$type as VerifyToken<TestRole>>::verify_token(&__ITEM, &TestProvider, token.token.as_ref())
            );

            std::assert!(std::matches!(res, Err(TokenVerifyError::NotBefore { .. })));
        }

        $($(crate::$extra!($type, TestProvider, TestRole => __ITEM);)*)?
    };

    ($(#[$meta:meta])* mod $mod_name:ident => $type:ty$(; $($extra:ident),* $(,)?)?) => {
        $(#[$meta])*
        mod $mod_name {
            $crate::define_tests!($type$(; $($extra),*)?);
        }
    };
}

#[cfg(any(
    // feature = "hs256", feature = "hs384", feature = "hs512",
    feature = "es256", feature = "es384", feature = "es512",
    feature = "rs256", feature = "rs384", feature = "rs512",
    feature = "ps256", feature = "ps384", feature = "ps512"
))]
fn encode_base64<E: base64ct::Encoding>(
    bytes: impl AsRef<[u8]>,
) -> Result<String, base64ct::Error> {
    let bytes = bytes.as_ref();
    let mut s = vec![0u8; bytes.len().div_ceil(3) * 4];

    let mut b64 = Encoder::<E>::new(&mut s)?;
    b64.encode(bytes)?;
    Ok(b64.finish()?.into())
}

#[cfg(any(
    feature = "rs256",
    feature = "rs384",
    feature = "rs512",
    feature = "ps256",
    feature = "ps384",
    feature = "ps512"
))]
fn common_make_key_rsa(
    alg: JwtAlgorithm,
    key: &rsa::RsaPublicKey,
    id: &Option<String>,
) -> crate::JwkContent {
    use rsa::traits::PublicKeyParts;

    crate::JwkContent {
        alg: Some(alg),
        kid: id.clone(),
        r#use: crate::JwkUse::Sig,
        key_ops: vec![crate::JwkKeyOp::Verify],
        x5u: None,
        x5t: None,
        x5c: None,
        x5t_s256: None,
        key: crate::JwkKey::RSA {
            n: encode_base64::<base64ct::Base64Url>(key.n().to_bytes_be())
                .expect("encoding modulus failed"),
            e: encode_base64::<base64ct::Base64Url>(key.e().to_bytes_be())
                .expect("encoding exponent failed"),
            private_key: None,
        },
    }
}

#[cfg(any(
    feature = "rs256",
    feature = "rs384",
    feature = "rs512",
    feature = "ps256",
    feature = "ps384",
    feature = "ps512"
))]
fn common_make_private_key_rsa(
    alg: JwtAlgorithm,
    key: &rsa::RsaPrivateKey,
    id: &Option<String>,
) -> crate::JwkContent {
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};

    crate::JwkContent {
        alg: Some(alg),
        kid: id.clone(),
        r#use: crate::JwkUse::Sig,
        key_ops: vec![crate::JwkKeyOp::Verify, crate::JwkKeyOp::Sign],
        x5u: None,
        x5t: None,
        x5c: None,
        x5t_s256: None,
        key: crate::JwkKey::RSA {
            n: encode_base64::<base64ct::Base64Url>(key.n().to_bytes_be())
                .expect("encoding modulus failed"),
            e: encode_base64::<base64ct::Base64Url>(key.e().to_bytes_be())
                .expect("encoding exponent failed"),
            private_key: Some(crate::JwkRSAPrivateKey {
                d: encode_base64::<base64ct::Base64Url>(key.d().to_bytes_be())
                    .expect("encoding private exponent failed"),
                p: Some(
                    encode_base64::<base64ct::Base64Url>(key.primes()[0].to_bytes_be())
                        .expect("encoding first prime failed"),
                ),
                q: Some(
                    encode_base64::<base64ct::Base64Url>(key.primes()[1].to_bytes_be())
                        .expect("encoding second prime failed"),
                ),
                dp: key.dp().map(|dp| {
                    encode_base64::<base64ct::Base64Url>(dp.to_bytes_be())
                        .expect("encoding first factor crt exponent failed")
                }),
                dq: key.dq().map(|dq| {
                    encode_base64::<base64ct::Base64Url>(dq.to_bytes_be())
                        .expect("encoding second factor crt exponent failed")
                }),
                qi: None,
                oth: vec![],
            }),
        },
    }
}

#[cfg(test)]
mod test_common {
    use crate::tokens::{SignToken, TokenVerifyError, Unsigned, VerifyToken};
    use crate::{GeneralError, JwtAlgorithm, JwtClaims, JwtHeader, Provider, RefOrOwned, Role};
    use rocket::response::Responder;
    use rocket::serde::json::Json;
    use rocket::{Route, async_trait};
    use std::convert::Infallible;
    use std::fmt::{Display, Formatter};

    pub struct TestProvider;

    impl Provider for TestProvider {
        type ClientError = GeneralError;
        type HeaderExtra = ();

        fn make_responder<'r>(&self, error: Self::ClientError) -> impl Responder<'r, 'static> {
            Json(error)
        }

        fn get_verifier<R: Role<Provider = Self, HeaderExtra = Self::HeaderExtra>>(
            &'_ self,
            _: JwtAlgorithm,
            _: &JwtHeader,
        ) -> Result<RefOrOwned<'_, dyn VerifyToken<R> + Send + Sync>, TokenVerifyError<R>> {
            unreachable!()
        }

        fn routes() -> impl IntoIterator<Item = Route> {
            []
        }
    }

    #[derive(PartialEq, Eq, Debug, Clone)]
    pub struct TestRole(pub JwtClaims);

    impl Display for TestRole {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.write_str("test role")
        }
    }

    #[async_trait]
    impl Role for TestRole {
        type Provider = TestProvider;
        type Scope = [&'static str];
        type ValidationError = Infallible;
        type ClaimsExtra = ();
        type HeaderExtra = ();

        fn into_claims(self) -> Result<JwtClaims<Self::ClaimsExtra>, Self::ValidationError> {
            Ok(self.0)
        }

        async fn from_claims(
            _: &Self::Provider,
            claims: JwtClaims<Self::ClaimsExtra>,
        ) -> Result<Self, Self::ValidationError> {
            Ok(Self(claims))
        }

        fn scope(&self) -> &Self::Scope {
            &[]
        }

        fn get_signer<'p>(
            &'_ self,
            _: &'p Self::Provider,
        ) -> RefOrOwned<'p, dyn SignToken<Self> + Send + Sync> {
            unreachable!()
        }
    }

    impl Unsigned {
        pub fn test_item() -> Self {
            Self::new()
        }
    }

    define_tests!(mod none => Unsigned);
}
