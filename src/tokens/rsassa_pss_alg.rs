#![cfg(any(feature = "ps256", feature = "ps384", feature = "ps512"))]

use crate::JwtClaims;

trait KeyConfiguration<const SIZE: usize, Signature> {
    type Key;
    type Header;
}

macro_rules! implement {
    ($($(#[$meta:meta])* [$feature:literal]type $name:ident: $bits:literal = ($signature:ty; $signing_key:ty, $verifying_key:ty);)*) => {
        $($(#[$meta])*
        #[cfg(any(feature = $feature, feature = "ps-all"))]
        #[allow(private_bounds)]
        pub struct $name<T: KeyConfiguration<$bits, $signature>> {
            key: T::Key,
            #[allow(unused)]
            header: T::Header,
            id: Option<String>,
        })*

        #[allow(private_bounds)]
        const _: () = {
            use crate::secret::SecretStr;
            use crate::tokens::{SignToken, TokenSignError, TokenSignResult, TokenVerifyError, VerifyToken};
            use crate::{JwtAlgorithm, JwtHeader, Role};
            use base64ct::{Base64UrlUnpadded, Decoder, Encoder};
            use signature::{Verifier, Signer, Keypair};
            use rocket::async_trait;
            use chrono::{DateTime, Utc};
            
            $(
                #[cfg(any(feature = $feature, feature = "ps-all"))]
                impl KeyConfiguration<$bits, $signature> for super::PublicKey {
                    type Key = $verifying_key;
                    type Header = ();
                }

                #[cfg(any(feature = $feature, feature = "ps-all"))]
                impl KeyConfiguration<$bits, $signature> for super::PrivateKey {
                    type Key = ($signing_key, $verifying_key);
                    type Header = Box<str>;
                }

                #[cfg(any(feature = $feature, feature = "ps-all"))]
                impl $name<super::PublicKey> {
                    pub fn from_key(key: $verifying_key) -> Self {
                        Self {
                            key,
                            header: (),
                            id: None,
                        }
                    }

                    pub fn from_key_with_id(key: $verifying_key, id: &str) -> Self {
                        Self {
                            key,
                            header: (),
                            id: Some(id.into()),
                        }
                    }

                    pub fn as_key(&self) -> crate::JwkContent {
                        super::common_make_key_rsa(JwtAlgorithm::$name, self.key.as_ref(), &self.id)
                    }
                }

                #[cfg(any(feature = $feature, feature = "ps-all"))]
                impl $name<super::PrivateKey> {
                    fn from_key_0(key: $signing_key, id: Option<&str>) -> Self {
                        let mut bytes = vec![0u8; 64];
                        let mut enc = Encoder::<Base64UrlUnpadded>::new(&mut bytes).unwrap();

                        enc.encode(
                            &serde_json::to_vec(&JwtHeader {
                                alg: JwtAlgorithm::$name,
                                ..Default::default()
                            })
                            .unwrap(),
                        )
                        .unwrap();

                        let verifying_key = key.verifying_key();
                        Self {
                            key: (key, verifying_key),
                            header: enc.finish().unwrap().into(),
                            id: id.map(Into::into)
                        }
                    }

                    pub fn from_key(key: $signing_key) -> Self {
                        Self::from_key_0(key, None)
                    }

                    pub fn from_key_with_id(key: $signing_key, id: &str) -> Self {
                        Self::from_key_0(key, Some(id))
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
                #[cfg(any(feature = $feature, feature = "ps-all"))]
                impl<R: Role> SignToken<R> for $name<super::PrivateKey> {
                    async fn sign_token(&self, role: R) -> Result<TokenSignResult, TokenSignError<R>> {
                        let claims = role.into_claims().map_err(TokenSignError::Validation)?;
                        let body = serde_json::to_vec(&claims)?;
                        let mut b64 = vec![0u8; std::cmp::max(body.len() * 2, 1024)];
                        let mut enc = Encoder::<Base64UrlUnpadded>::new(&mut b64)?;
                        enc.encode(&body)?;
                        let mut signable = format!("{}.{}", self.header, enc.finish()?);
                
                        let signature: $signature = <$signing_key as Signer<$signature>>::sign(&self.key.0, signable.as_bytes());
                
                        enc = Encoder::<Base64UrlUnpadded>::new(&mut b64)?;
                        enc.encode(&Box::<[u8]>::from(signature))?;
                        signable.push('.');
                        signable.push_str(enc.finish()?);

                        Ok(TokenSignResult {
                            token: signable.into(),
                            expires: claims.expires.unwrap_or(DateTime::<Utc>::MAX_UTC),
                        })
                    }
                }

                #[cfg(any(feature = $feature, feature = "ps-all"))]
                impl<T: KeyConfiguration<$bits, $signature>> $name<T> {
                    async fn verify<R: Role>(key: &$verifying_key, provider: &R::Provider, token: &SecretStr) -> Result<R, TokenVerifyError<R>> {
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
                #[cfg(any(feature = $feature, feature = "ps-all"))]
                impl<R: Role> VerifyToken<R> for $name<super::PrivateKey> {
                    async fn verify_token(&self, provider: &R::Provider, token: &SecretStr) -> Result<R, TokenVerifyError<R>> {
                        Self::verify::<R>(&self.key.1, provider, token).await
                    }
                }

                #[async_trait]
                #[cfg(any(feature = $feature, feature = "ps-all"))]
                impl<R: Role> VerifyToken<R> for $name<super::PublicKey> {
                    async fn verify_token(&self, provider: &R::Provider, token: &SecretStr) -> Result<R, TokenVerifyError<R>> {
                        Self::verify::<R>(&self.key, provider, token).await
                    }
                }
            )*
        };
    };
}

implement! {
    ["ps256"] type PS256: 256 = (rsa::pss::Signature; rsa::pss::SigningKey<sha2::Sha256>, rsa::pss::VerifyingKey<sha2::Sha256>);
    ["ps384"] type PS384: 384 = (rsa::pss::Signature; rsa::pss::SigningKey<sha2::Sha384>, rsa::pss::VerifyingKey<sha2::Sha384>);
    ["ps512"] type PS512: 512 = (rsa::pss::Signature; rsa::pss::SigningKey<sha2::Sha512>, rsa::pss::VerifyingKey<sha2::Sha512>);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokens::PrivateKey;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::RsaPrivateKey;

    const PEM: &str = include_str!("rsatestkey.pem");

    #[cfg(feature = "ps256")]
    impl PS256<PrivateKey> {
        fn test_item() -> Self {
            Self::from_key(rsa::pss::SigningKey::new(RsaPrivateKey::from_pkcs8_pem(PEM).unwrap()))
        }
    }

    #[cfg(feature = "ps384")]
    impl PS384<PrivateKey> {
        fn test_item() -> Self {
            Self::from_key(rsa::pss::SigningKey::new(RsaPrivateKey::from_pkcs8_pem(PEM).unwrap()))
        }
    }

    #[cfg(feature = "ps512")]
    impl PS512<PrivateKey> {
        fn test_item() -> Self {
            Self::from_key(rsa::pss::SigningKey::new(RsaPrivateKey::from_pkcs8_pem(PEM).unwrap()))
        }
    }

    crate::define_tests!(#[cfg(feature = "ps256")] mod ps256 => PS256<PrivateKey>);
    crate::define_tests!(#[cfg(feature = "ps384")] mod ps384 => PS384<PrivateKey>);
    crate::define_tests!(#[cfg(feature = "ps512")] mod ps512 => PS512<PrivateKey>);
}
