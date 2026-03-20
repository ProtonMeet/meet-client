use crate::{KbtCwtTagged, SdCwtIssuedTagged, SdCwtVerified};
use mls_spec::defs::CiphersuiteId;
use proton_claims::reexports::{CustomClaims, Select, coset};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum SignatureScheme {
    Ed25519,
    Ed448,
    P256,
    P384,
    P521,
}

pub trait MlsIdentityExt {
    /// Given a signature scheme can correspond to many MLS ciphersuites this method lists them all
    fn supported_mls_ciphersuites(&self) -> Option<Vec<CiphersuiteId>>;

    /// Tries to guess the signature scheme of the credential if possible
    fn signature_scheme(&self) -> Option<SignatureScheme>;
}

impl<T: Select> MlsIdentityExt for SdCwtIssuedTagged<T, sha2::Sha256> {
    fn supported_mls_ciphersuites(&self) -> Option<Vec<CiphersuiteId>> {
        let payload = self.0.payload.as_value().ok()?;
        let (alg, crv) = (payload.cnf.alg(), payload.cnf.crv());
        match (alg, crv) {
            (Some(coset::iana::Algorithm::EdDSA), Some(coset::iana::EllipticCurve::Ed25519)) => Some(vec![
                CiphersuiteId::new_unchecked(CiphersuiteId::MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519),
                CiphersuiteId::new_unchecked(CiphersuiteId::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519),
            ]),
            (Some(coset::iana::Algorithm::EdDSA), Some(coset::iana::EllipticCurve::Ed448)) => Some(vec![
                CiphersuiteId::new_unchecked(CiphersuiteId::MLS_256_DHKEMX448_AES256GCM_SHA512_ED448),
                CiphersuiteId::new_unchecked(CiphersuiteId::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_ED448),
            ]),
            (Some(coset::iana::Algorithm::ES256), Some(coset::iana::EllipticCurve::P_256)) => {
                Some(vec![CiphersuiteId::new_unchecked(
                    CiphersuiteId::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
                )])
            }
            (Some(coset::iana::Algorithm::ES384), Some(coset::iana::EllipticCurve::P_384)) => {
                Some(vec![CiphersuiteId::new_unchecked(
                    CiphersuiteId::MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
                )])
            }
            (Some(coset::iana::Algorithm::ES512), Some(coset::iana::EllipticCurve::P_521)) => {
                Some(vec![CiphersuiteId::new_unchecked(
                    CiphersuiteId::MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
                )])
            }
            _ => None,
        }
    }

    fn signature_scheme(&self) -> Option<SignatureScheme> {
        let payload = self.0.payload.as_value().ok()?;
        let (alg, crv) = (payload.cnf.alg(), payload.cnf.crv());
        match (alg, crv) {
            (Some(coset::iana::Algorithm::EdDSA), Some(coset::iana::EllipticCurve::Ed25519)) => {
                Some(SignatureScheme::Ed25519)
            }
            (Some(coset::iana::Algorithm::EdDSA), Some(coset::iana::EllipticCurve::Ed448)) => {
                Some(SignatureScheme::Ed448)
            }
            (Some(coset::iana::Algorithm::ES256), Some(coset::iana::EllipticCurve::P_256)) => {
                Some(SignatureScheme::P256)
            }
            (Some(coset::iana::Algorithm::ES384), Some(coset::iana::EllipticCurve::P_384)) => {
                Some(SignatureScheme::P384)
            }
            (Some(coset::iana::Algorithm::ES512), Some(coset::iana::EllipticCurve::P_521)) => {
                Some(SignatureScheme::P521)
            }
            _ => None,
        }
    }
}

impl<T: Select> MlsIdentityExt for SdCwtVerified<T, sha2::Sha256> {
    fn supported_mls_ciphersuites(&self) -> Option<Vec<CiphersuiteId>> {
        self.0.supported_mls_ciphersuites()
    }

    fn signature_scheme(&self) -> Option<SignatureScheme> {
        self.0.signature_scheme()
    }
}

impl<T: Select, U: CustomClaims> MlsIdentityExt for KbtCwtTagged<T, sha2::Sha256, U> {
    fn supported_mls_ciphersuites(&self) -> Option<Vec<CiphersuiteId>> {
        self.0
            .protected
            .as_value()
            .ok()?
            .kcwt
            .clone_value()
            .ok()?
            .supported_mls_ciphersuites()
    }

    fn signature_scheme(&self) -> Option<SignatureScheme> {
        self.0
            .protected
            .as_value()
            .ok()?
            .kcwt
            .clone_value()
            .ok()?
            .signature_scheme()
    }
}
