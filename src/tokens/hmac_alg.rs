#![cfg(any(feature = "hs256", feature = "hs384", feature = "hs512"))]

use crate::secret::SecretStr;
use crate::tokens::{
    SignToken, TokenSignError, TokenSignResult, TokenVerifyError, VerifyToken, encode_base64,
};
use crate::{Combine, JwtAlgorithm, JwtClaims, JwtHeader, Role};
use base64ct::{Base64UrlUnpadded, Decoder, Encoder};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use rocket::async_trait;
use std::borrow::Cow;
use serde::Serialize;

macro_rules! implement {
    ($($(#[$meta:meta])* [$feature:literal]type $name:ident: $bits:literal = $sha:ty;)*) => {
        $($(#[$meta])*
        #[cfg(any(feature = $feature, feature = "hs-all"))]
        pub struct $name<Extra = ()> {
            hmac: ::hmac::Hmac<$sha>,
            header: Box<str>,
            header_base: JwtHeader<Extra>,
        })*

        const _: () = {


            $(
                #[cfg(any(feature = $feature, feature = "hs-all"))]
                impl<Extra: Serialize> $name<Extra> {
                    pub fn new_with_header(secret: &SecretStr, header: JwtHeader<Extra>) -> Self {
                        let header = JwtHeader::<Extra> {
                            alg: JwtAlgorithm::$name,
                            ..header
                        };
                        let json = serde_json::to_vec(&header).unwrap();

                        let mut bytes = vec![0u8; json.len().div_ceil(3) * 5];
                        let mut enc = Encoder::<Base64UrlUnpadded>::new(&mut bytes).unwrap();

                        enc.encode(&json[..]).unwrap();

                        Self {
                            // this is infallible
                            hmac: Hmac::<$sha>::new_from_slice(secret.expose_bytes()).unwrap(),
                            header: enc.finish().unwrap().into(),
                            header_base: header
                        }
                    }

                    pub fn new(secret: &SecretStr) -> Self 
                        where JwtHeader<Extra>: Default
                    {
                        Self::new_with_header(secret, Default::default())
                    }
                }

                #[async_trait]
                #[cfg(any(feature = $feature, feature = "hs-all"))]
                impl<R: Role<HeaderExtra = Extra>, Extra: Serialize + Combine + Send + Sync> SignToken<R> for $name<Extra> {
                    async fn sign_token(&self, role: R, header: Option<JwtHeader<Extra>>) -> Result<TokenSignResult, TokenSignError<R>> {
                        let claims = role.into_claims().map_err(TokenSignError::Validation)?;
                        let header = match R::construct_header(&claims, header) {
                            None => Cow::Borrowed(self.header.as_ref()),
                            Some(h) => Cow::Owned(encode_base64::<Base64UrlUnpadded>(serde_json::to_vec(&(&self.header_base + h))?)?)
                        };
                        let body = serde_json::to_vec(&claims)?;
                        let mut signable = format!("{}.{}", header, encode_base64::<Base64UrlUnpadded>(body)?);

                        let mut hmac = self.hmac.clone();
                        hmac.update(signable.as_bytes());

                        signable.push('.');
                        signable.push_str(&encode_base64::<Base64UrlUnpadded>(hmac.finalize().into_bytes())?);

                        Ok(TokenSignResult {
                            token: signable.into(),
                            expires: claims.expires.unwrap_or(DateTime::<Utc>::MAX_UTC),
                        })
                    }
                }

                #[async_trait]
                #[cfg(any(feature = $feature, feature = "hs-all"))]
                impl<R: Role> VerifyToken<R> for $name<R::HeaderExtra> {
                    async fn verify_token(&self, provider: &R::Provider, token: &SecretStr) -> Result<R, TokenVerifyError<R>> {
                        let (content, signature) = token
                            .rsplit_once('.')
                            .ok_or(TokenVerifyError::UnparsableInput)?;

                        let mut bytes = Vec::<u8>::new();
                        let mut dec = Decoder::<Base64UrlUnpadded>::new(signature.expose_bytes())?;
                        let signature = dec.decode_to_end(&mut bytes)?;
                        let mut hmac = self.hmac.clone();
                        hmac.update(content.expose_bytes());

                        match hmac.verify_slice(signature) {
                            Ok(()) => {
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

                            Err(_) => Err(TokenVerifyError::SignatureCheckFailed),
                        }
                    }
                }
            )*
        };
    };
}

implement! {
    ["hs256"] type HS256: 256 = sha2::Sha256;
    ["hs384"] type HS384: 384 = sha2::Sha384;
    ["hs512"] type HS512: 512 = sha2::Sha512;
}

#[cfg(test)]
mod tests {
    use crate::secret::SecretStr;
    use crate::tokens::{HS256, HS384, HS512};

    #[cfg(feature = "hs256")]
    impl HS256 {
        fn test_item() -> Self {
            Self::new(SecretStr::new("Hello, world!"))
        }
    }

    #[cfg(feature = "hs384")]
    impl HS384 {
        fn test_item() -> Self {
            Self::new(SecretStr::new("Hello, world!"))
        }
    }

    #[cfg(feature = "hs512")]
    impl HS512 {
        fn test_item() -> Self {
            Self::new(SecretStr::new("Hello, world!"))
        }
    }

    crate::define_tests!(#[cfg(feature = "hs256")] mod hs256 => HS256);
    crate::define_tests!(#[cfg(feature = "hs384")] mod hs384 => HS384);
    crate::define_tests!(#[cfg(feature = "hs512")] mod hs512 => HS512);
}
