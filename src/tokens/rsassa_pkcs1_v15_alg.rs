#![cfg(any(feature = "rs256", feature = "rs384", feature = "rs512"))]

use crate::secret::SecretStr;
use crate::tokens::{
    SignToken, TokenSignError, TokenSignResult, TokenVerifyError, VerifyToken, encode_base64,
};
use crate::jwt::{JwtAlgorithm, JwtClaims, JwtHeader};
use crate::{Combine, Role};
use base64ct::{Base64UrlUnpadded, Decoder, Encoder};
use chrono::{DateTime, Utc};
use rocket::async_trait;
use signature::rand_core::OsRng;
use signature::{Keypair, Signer, Verifier};
use std::borrow::Cow;
use serde::Serialize;

trait KeyConfiguration<const SIZE: usize, Signature> {
    type Key;
    type Header;
}

macro_rules! implement {
    ($($(#[$meta:meta])* [$feature:literal]type $name:ident: $bits:literal = ($signature:ty; $signing_key:ty, $verifying_key:ty);)*) => {
        $($(#[$meta])*
        #[cfg(any(feature = $feature, feature = "rs-all"))]
        #[allow(private_bounds)]
        pub struct $name<T: KeyConfiguration<$bits, $signature>, Extra = ()> {
            key: T::Key,
            #[allow(unused)]
            header: T::Header,
            header_base: JwtHeader<Extra>,
            id: Option<String>,
        })*

        #[allow(private_bounds)]
        const _: () = {$(
            #[cfg(any(feature = $feature, feature = "rs-all"))]
            impl KeyConfiguration<$bits, $signature> for super::PublicKey {
                type Key = $verifying_key;
                type Header = ();
            }

            #[cfg(any(feature = $feature, feature = "rs-all"))]
            impl KeyConfiguration<$bits, $signature> for super::PrivateKey {
                type Key = ($signing_key, $verifying_key);
                type Header = Box<str>;
            }

            #[cfg(any(feature = $feature, feature = "rs-all"))]
            impl<Extra: Default> $name<super::PublicKey, Extra> {
                pub fn from_key(key: $verifying_key) -> Self {
                    Self {
                        key,
                        header: (),
                        header_base: Default::default(),
                        id: None,
                    }
                }

                pub fn from_key_with_id(key: $verifying_key, id: &str) -> Self {
                    Self {
                        key,
                        header: (),
                        header_base: Default::default(),
                        id: Some(id.into()),
                    }
                }

                pub fn as_key(&self) -> crate::JwkContent {
                    super::common_make_key_rsa(JwtAlgorithm::$name, self.key.as_ref(), &self.id)
                }
            }

            #[cfg(any(feature = $feature, feature = "rs-all"))]
            impl<Extra: Serialize> $name<super::PrivateKey, Extra> {
                pub fn new_with(key: $signing_key, header: JwtHeader<Extra>) -> Self {
                    let header = JwtHeader::<Extra> {
                        alg: JwtAlgorithm::$name,
                        ..header
                    };
                    let json = serde_json::to_vec(&header).unwrap();
                    let mut bytes = vec![0u8; json.len().div_ceil(3) * 4];
                    let mut enc = Encoder::<Base64UrlUnpadded>::new(&mut bytes).unwrap();

                    enc.encode(&json[..]).unwrap();

                    let verifying_key = key.verifying_key();
                    Self {
                        key: (key, verifying_key),
                        header: enc.finish().unwrap().into(),
                        id: header.kid.clone().map(Into::into),
                        header_base: header,
                    }
                }

                pub fn from_key(key: $signing_key) -> Self
                    where JwtHeader<Extra>: Default
                {
                    Self::new_with(key, Default::default())
                }

                pub fn from_key_with(key: $signing_key, header: JwtHeader<Extra>) -> Self {
                    Self::new_with(key, header)
                }

                pub fn from_key_with_id(key: $signing_key, id: impl Into<String>) -> Self 
                    where JwtHeader<Extra>: Default
                {
                    Self::new_with(key, JwtHeader::<Extra> {
                        kid: Some(id.into()),
                        ..Default::default()
                    })
                }

                pub fn random(bit_size: usize) -> rsa::Result<Self>
                    where JwtHeader<Extra>: Default
                {
                    Ok(Self::from_key(<$signing_key>::random(&mut OsRng::default(), bit_size)?))
                }

                pub fn random_with(bit_size: usize, header: JwtHeader<Extra>) -> rsa::Result<Self> {
                    Ok(Self::from_key_with(<$signing_key>::random(&mut OsRng::default(), bit_size)?, header))
                }

                pub fn random_with_id(bit_size: usize, id: impl Into<String>) -> rsa::Result<Self>
                    where JwtHeader<Extra>: Default
                {
                    Ok(Self::from_key_with_id(<$signing_key>::random(&mut OsRng::default(), bit_size)?, id))
                }

                pub fn as_key(&self) -> crate::JwkContent {
                    super::common_make_key_rsa(JwtAlgorithm::$name, self.key.1.as_ref(), &self.id)
                }

                #[deprecated = "This method will EXPOSE this private key! If you are 100% absolutely **positively** sure about this, use #[allow(deprecated)]."]
                pub fn as_private_key_exposed(&self) -> crate::JwkContent {
                    super::common_make_private_key_rsa(JwtAlgorithm::$name, self.key.0.as_ref(), &self.id)
                }
            }

            #[async_trait]
            #[cfg(any(feature = $feature, feature = "rs-all"))]
            impl<R: Role<HeaderExtra = Extra>, Extra: Serialize + Combine + Send + Sync> SignToken<R> for $name<super::PrivateKey, Extra> {
                async fn sign_token(&self, role: R, header: Option<JwtHeader<Extra>>) -> Result<TokenSignResult, TokenSignError<R>> {
                    let claims = role.into_claims().map_err(TokenSignError::Validation)?;
                    let header = match R::construct_header(&claims, header) {
                        None => Cow::Borrowed(self.header.as_ref()),
                        Some(h) => Cow::Owned(encode_base64::<Base64UrlUnpadded>(serde_json::to_vec(&(&self.header_base + h))?)?)
                    };
                    let body = serde_json::to_vec(&claims)?;
                    let mut signable = format!("{}.{}", header, encode_base64::<Base64UrlUnpadded>(body)?);

                    let signature: $signature = <$signing_key as Signer<$signature>>::sign(&self.key.0, signable.as_bytes());

                    signable.push('.');
                    signable.push_str(&encode_base64::<Base64UrlUnpadded>(&Box::<[u8]>::from(signature))?);

                    Ok(TokenSignResult {
                        token: signable.into(),
                        expires: claims.expires.unwrap_or(DateTime::<Utc>::MAX_UTC),
                    })
                }
            }

            #[cfg(any(feature = $feature, feature = "rs-all"))]
            impl<T: KeyConfiguration<$bits, $signature>, Extra> $name<T, Extra> {
                async fn verify<R: Role<HeaderExtra = Extra>>(key: &$verifying_key, provider: &R::Provider, token: &SecretStr) -> Result<R, TokenVerifyError<R>> {
                    let (content, signature) = token
                            .rsplit_once('.')
                            .ok_or(TokenVerifyError::UnparsableInput)?;

                    let mut bytes = Vec::<u8>::new();
                    let mut dec = Decoder::<Base64UrlUnpadded>::new(signature.expose_bytes())?;
                    let signature = dec.decode_to_end(&mut bytes)?;
                    let signature = <$signature>::try_from(signature).map_err(|_| TokenVerifyError::UnparsableInput)?;

                    key.verify(content.expose_bytes(), &signature)
                        .map_err(|_| TokenVerifyError::SignatureCheckFailed)?;

                    let (_header, content) = content
                        .split_once('.')
                        .ok_or(TokenVerifyError::UnparsableInput)?;
                    let mut bytes = Vec::<u8>::new();
                    Decoder::<Base64UrlUnpadded>::new(content.expose_bytes())?
                        .decode_to_end(&mut bytes)?;
                    let role: JwtClaims<R::ClaimsExtra> = serde_json::from_slice(&bytes)?;

                    let now = Utc::now();
                    if let Some(expires) = role.expires && expires < now {
                        return Err(TokenVerifyError::Expired {
                            now,
                            expires
                        })
                    }

                    if let Some(not_before) = role.not_before.or(role.issued_at) && not_before > now {
                        return Err(TokenVerifyError::NotBefore {
                            now,
                            not_before
                        })
                    }

                    Ok(R::from_claims(provider, role).await.map_err(TokenVerifyError::Validation)?)
                }
            }

            #[async_trait]
            #[cfg(any(feature = $feature, feature = "rs-all"))]
            impl<R: Role> VerifyToken<R> for $name<super::PrivateKey, R::HeaderExtra> {
                async fn verify_token(&self, provider: &R::Provider, token: &SecretStr) -> Result<R, TokenVerifyError<R>> {
                    Self::verify::<R>(&self.key.1, provider, token).await
                }
            }

            #[async_trait]
            #[cfg(any(feature = $feature, feature = "rs-all"))]
            impl<R: Role> VerifyToken<R> for $name<super::PublicKey, R::HeaderExtra> {
                async fn verify_token(&self, provider: &R::Provider, token: &SecretStr) -> Result<R, TokenVerifyError<R>> {
                    Self::verify::<R>(&self.key, provider, token).await
                }
            }
        )*};
    };
}

implement! {
    ["rs256"] type RS256: 256 = (rsa::pkcs1v15::Signature; rsa::pkcs1v15::SigningKey<sha2::Sha256>, rsa::pkcs1v15::VerifyingKey<sha2::Sha256>);
    ["rs384"] type RS384: 384 = (rsa::pkcs1v15::Signature; rsa::pkcs1v15::SigningKey<sha2::Sha384>, rsa::pkcs1v15::VerifyingKey<sha2::Sha384>);
    ["rs512"] type RS512: 512 = (rsa::pkcs1v15::Signature; rsa::pkcs1v15::SigningKey<sha2::Sha512>, rsa::pkcs1v15::VerifyingKey<sha2::Sha512>);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokens::PrivateKey;
    use rsa::pkcs8::DecodePrivateKey;

    const PEM: &str = include_str!("rsatestkey.pem");

    #[cfg(feature = "rs256")]
    impl RS256<PrivateKey> {
        fn test_item() -> Self {
            Self::from_key(rsa::pkcs1v15::SigningKey::from_pkcs8_pem(PEM).unwrap())
        }
    }

    #[cfg(feature = "rs384")]
    impl RS384<PrivateKey> {
        fn test_item() -> Self {
            Self::from_key(rsa::pkcs1v15::SigningKey::from_pkcs8_pem(PEM).unwrap())
        }
    }

    #[cfg(feature = "rs512")]
    impl RS512<PrivateKey> {
        fn test_item() -> Self {
            Self::from_key(rsa::pkcs1v15::SigningKey::from_pkcs8_pem(PEM).unwrap())
        }
    }

    crate::define_tests!(#[cfg(feature = "rs256")] mod rs256 => RS256<PrivateKey>);
    crate::define_tests!(#[cfg(feature = "rs384")] mod rs384 => RS384<PrivateKey>);
    crate::define_tests!(#[cfg(feature = "rs512")] mod rs512 => RS512<PrivateKey>);
}
