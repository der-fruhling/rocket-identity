#![cfg(any(feature = "es256", feature = "es384", feature = "es512"))]

use crate::secret::SecretStr;
use crate::tokens::encode_base64;
use crate::tokens::{SignToken, TokenSignError, TokenSignResult, TokenVerifyError, VerifyToken};
use crate::{JwkEllipticCurve, JwkKey, JwkKeyOp, JwkUse, JwtAlgorithm, JwtClaims, JwtHeader, Role};
use base64ct::{Base64Url, Base64UrlUnpadded, Decoder, Encoder};
use chrono::{DateTime, Utc};
use ecdsa::elliptic_curve::sec1::ModulusSize;
use ecdsa::elliptic_curve::{CurveArithmetic, FieldBytes, NonZeroScalar};
use rocket::async_trait;
use signature::rand_core::OsRng;
use signature::{Signer, Verifier};

trait KeyConfiguration<const SIZE: usize, Signature> {
    type Key;
    type Header;
}

fn common_make_key<C: CurveArithmetic>(
    alg: JwtAlgorithm,
    crv: JwkEllipticCurve,
    affine_point: &impl ecdsa::elliptic_curve::sec1::ToEncodedPoint<C>,
    id: &Option<String>,
) -> crate::JwkContent
where
    <C as ecdsa::elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
{
    use ecdsa::elliptic_curve::sec1::EncodedPoint;

    let affine_point: EncodedPoint<C> = affine_point.to_encoded_point(false);
    crate::JwkContent {
        alg: Some(alg),
        kid: id.clone(),
        r#use: JwkUse::Sig,
        key_ops: vec![JwkKeyOp::Verify],
        x5u: None,
        x5t: None,
        x5c: None,
        x5t_s256: None,
        key: JwkKey::EC {
            crv,
            x: encode_base64::<Base64Url>(affine_point.x().unwrap()).expect("failed to encode x"),
            y: encode_base64::<Base64Url>(affine_point.y().unwrap()).expect("failed to encode y"),
            d: None,
        },
    }
}

fn common_make_private_key<C: CurveArithmetic>(
    alg: JwtAlgorithm,
    crv: JwkEllipticCurve,
    affine_point: &impl ecdsa::elliptic_curve::sec1::ToEncodedPoint<C>,
    secret_scalar: &NonZeroScalar<C>,
    id: &Option<String>,
) -> crate::JwkContent
where
    <C as ecdsa::elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
{
    use ecdsa::elliptic_curve::sec1::EncodedPoint;

    let affine_point: EncodedPoint<C> = affine_point.to_encoded_point(false);
    let secret: FieldBytes<C> = (*secret_scalar.as_ref()).into();
    crate::JwkContent {
        alg: Some(alg),
        kid: id.clone(),
        r#use: JwkUse::Sig,
        key_ops: vec![JwkKeyOp::Verify, JwkKeyOp::Sign],
        x5u: None,
        x5t: None,
        x5c: None,
        x5t_s256: None,
        key: JwkKey::EC {
            crv,
            x: encode_base64::<Base64Url>(affine_point.x().unwrap()).expect("failed to encode x"),
            y: encode_base64::<Base64Url>(affine_point.y().unwrap()).expect("failed to encode y"),
            d: Some(
                encode_base64::<Base64Url>(&secret[..]).expect("failed to encode secret scalar"),
            ),
        },
    }
}

macro_rules! implement {
    ($($(#[$meta:meta])* [$feature:literal]type $name:ident($crv:ident): $bits:literal = ($signature:ty; $signing_key:ty, $verifying_key:ty);)*) => {
        $($(#[$meta])*
        #[cfg(any(feature = $feature, feature = "es-all"))]
        #[allow(private_bounds)]
        pub struct $name<T: KeyConfiguration<$bits, $signature>> {
            key: T::Key,
            #[allow(unused)]
            header: T::Header,
            id: Option<String>,
        })*

        #[allow(private_bounds)]
        const _: () = {

            $(
                #[cfg(any(feature = $feature, feature = "es-all"))]
                impl KeyConfiguration<$bits, $signature> for super::PublicKey {
                    type Key = $verifying_key;
                    type Header = ();
                }

                #[cfg(any(feature = $feature, feature = "es-all"))]
                impl KeyConfiguration<$bits, $signature> for super::PrivateKey {
                    type Key = ($signing_key, $verifying_key);
                    type Header = Box<str>;
                }

                #[cfg(any(feature = $feature, feature = "es-all"))]
                impl $name<super::PublicKey> {
                    pub fn from_key(key: $verifying_key) -> Self {
                        Self {
                            key,
                            header: (),
                            id: None
                        }
                    }

                    pub fn from_key_with_id(key: $verifying_key, id: &str) -> Self {
                        Self {
                            key,
                            header: (),
                            id: Some(id.into())
                        }
                    }

                    pub fn as_key(&self) -> crate::JwkContent {
                        common_make_key::<>(JwtAlgorithm::$name, JwkEllipticCurve::$crv, self.key.as_affine(), &self.id)
                    }
                }

                #[cfg(any(feature = $feature, feature = "es-all"))]
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

                        let verifying_key = <$verifying_key>::from(&key);
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

                    pub fn random() -> Self {
                        Self::from_key(<$signing_key>::random(&mut OsRng::default()))
                    }

                    pub fn random_with_id(id: &str) -> Self {
                        Self::from_key_with_id(<$signing_key>::random(&mut OsRng::default()), id)
                    }

                    pub fn as_key(&self) -> crate::JwkContent {
                        common_make_key(JwtAlgorithm::$name, JwkEllipticCurve::$crv, self.key.1.as_affine(), &self.id)
                    }

                    pub fn as_private_key_exposed(&self) -> crate::JwkContent {
                        common_make_private_key(JwtAlgorithm::$name, JwkEllipticCurve::$crv, self.key.1.as_affine(), self.key.0.as_nonzero_scalar(), &self.id)
                    }
                }

                #[async_trait]
                #[cfg(any(feature = $feature, feature = "es-all"))]
                impl<R: Role> SignToken<R> for $name<super::PrivateKey> {
                    async fn sign_token(&self, role: R) -> Result<TokenSignResult, TokenSignError<R>> {
                        let claims = role.into_claims().map_err(TokenSignError::Validation)?;
                        let body = serde_json::to_vec(&claims)?;
                        let mut b64 = vec![0u8; std::cmp::max(body.len() * 2, ($bits / 3) + 15)];
                        let mut enc = Encoder::<Base64UrlUnpadded>::new(&mut b64)?;
                        enc.encode(&body)?;
                        let mut signable = format!("{}.{}", self.header, enc.finish()?);

                        let signature: $signature = <$signing_key as Signer<$signature>>::sign(&self.key.0, signable.as_bytes());

                        enc = Encoder::<Base64UrlUnpadded>::new(&mut b64)?;
                        enc.encode(&signature.to_bytes())?;
                        signable.push('.');
                        signable.push_str(enc.finish()?);

                        Ok(TokenSignResult {
                            token: signable.into(),
                            expires: claims.expires.unwrap_or(DateTime::<Utc>::MAX_UTC),
                        })
                    }
                }

                #[cfg(any(feature = $feature, feature = "es-all"))]
                impl<T: KeyConfiguration<$bits, $signature>> $name<T> {
                    async fn verify<R: Role>(key: &$verifying_key, provider: &R::Provider, token: &SecretStr) -> Result<R, TokenVerifyError<R>> {
                        let (content, signature) = token
                                .rsplit_once('.')
                                .ok_or(TokenVerifyError::UnparsableInput)?;

                        let mut bytes = Vec::<u8>::new();
                        let mut dec = Decoder::<Base64UrlUnpadded>::new(signature.expose_bytes())?;
                        let signature = dec.decode_to_end(&mut bytes)?;
                        let signature = <$signature>::from_slice(signature).map_err(|_| TokenVerifyError::UnparsableInput)?;

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
                #[cfg(any(feature = $feature, feature = "es-all"))]
                impl<R: Role> VerifyToken<R> for $name<super::PrivateKey> {
                    async fn verify_token(&self, provider: &R::Provider, token: &SecretStr) -> Result<R, TokenVerifyError<R>> {
                        Self::verify::<R>(&self.key.1, provider, token).await
                    }
                }

                #[async_trait]
                #[cfg(any(feature = $feature, feature = "es-all"))]
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
    ["es256"] type ES256(P256): 256 = (p256::ecdsa::Signature; p256::ecdsa::SigningKey, p256::ecdsa::VerifyingKey);
    ["es384"] type ES384(P384): 384 = (p384::ecdsa::Signature; p384::ecdsa::SigningKey, p384::ecdsa::VerifyingKey);
    ["es512"] type ES512(P521): 512 = (p521::ecdsa::Signature; p521::ecdsa::SigningKey, p521::ecdsa::VerifyingKey);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokens::PrivateKey;
    use signature::rand_core::OsRng;

    #[cfg(feature = "es256")]
    impl ES256<PrivateKey> {
        fn test_item() -> Self {
            Self::from_key(p256::ecdsa::SigningKey::random(&mut OsRng::default()))
        }
    }

    #[cfg(feature = "es384")]
    impl ES384<PrivateKey> {
        fn test_item() -> Self {
            Self::from_key(p384::ecdsa::SigningKey::random(&mut OsRng::default()))
        }
    }

    #[cfg(feature = "es512")]
    impl ES512<PrivateKey> {
        fn test_item() -> Self {
            Self::from_key(p521::ecdsa::SigningKey::random(&mut OsRng::default()))
        }
    }

    crate::define_tests!(#[cfg(feature = "es256")] mod es256 => ES256<PrivateKey>; jwk_tests);
    crate::define_tests!(#[cfg(feature = "es384")] mod es384 => ES384<PrivateKey>; jwk_tests);
    crate::define_tests!(#[cfg(feature = "es512")] mod es512 => ES512<PrivateKey>; jwk_tests);
}
