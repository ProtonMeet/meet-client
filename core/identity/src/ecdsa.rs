use crate::IdentityError;
use proton_claims::{
    ProtonMeetClaims, UserAsserted,
    reexports::{
        Holder,
        spec::{NoClaims, reexports::coset},
    },
};

pub struct ProtonP256SdCwtHolder {
    signing_key: p256::ecdsa::SigningKey,
    verifying_key: p256::ecdsa::VerifyingKey,
}

impl TryFrom<&[u8]> for ProtonP256SdCwtHolder {
    type Error = IdentityError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let signing_key = p256::ecdsa::SigningKey::try_from(bytes).map_err(signature::Error::from_source)?;
        Ok(Self {
            verifying_key: *signing_key.as_ref(),
            signing_key,
        })
    }
}

impl signature::Signer<p256::ecdsa::Signature> for ProtonP256SdCwtHolder {
    fn try_sign(&self, msg: &[u8]) -> Result<p256::ecdsa::Signature, signature::Error> {
        self.signing_key.try_sign(msg)
    }
}

impl Holder for ProtonP256SdCwtHolder {
    type Error = IdentityError;
    type Signature = p256::ecdsa::Signature;
    type Verifier = p256::ecdsa::VerifyingKey;
    type Signer = p256::ecdsa::SigningKey;

    type Hasher = sha2::Sha256;

    type IssuerPayloadClaims = ProtonMeetClaims;
    type KbtPayloadClaims = UserAsserted;
    type IssuerProtectedClaims = NoClaims;
    type IssuerUnprotectedClaims = NoClaims;
    type KbtProtectedClaims = NoClaims;
    type KbtUnprotectedClaims = NoClaims;

    fn new(signing_key: Self::Signer) -> Self {
        Self {
            verifying_key: *signing_key.as_ref(),
            signing_key,
        }
    }

    fn signer(&self) -> &Self::Signer {
        &self.signing_key
    }

    fn cwt_algorithm(&self) -> coset::iana::Algorithm {
        coset::iana::Algorithm::ES256
    }

    fn verifier(&self) -> &Self::Verifier {
        &self.verifying_key
    }
}

pub struct ProtonP384SdCwtHolder {
    signing_key: p384::ecdsa::SigningKey,
    verifying_key: p384::ecdsa::VerifyingKey,
}

impl TryFrom<&[u8]> for ProtonP384SdCwtHolder {
    type Error = IdentityError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let signing_key = p384::ecdsa::SigningKey::try_from(bytes).map_err(signature::Error::from_source)?;
        Ok(Self {
            verifying_key: *signing_key.as_ref(),
            signing_key,
        })
    }
}

impl signature::Signer<p384::ecdsa::Signature> for ProtonP384SdCwtHolder {
    fn try_sign(&self, msg: &[u8]) -> Result<p384::ecdsa::Signature, signature::Error> {
        self.signing_key.try_sign(msg)
    }
}

impl Holder for ProtonP384SdCwtHolder {
    type Error = IdentityError;
    type Signature = p384::ecdsa::Signature;
    type Signer = p384::ecdsa::SigningKey;
    type Verifier = p384::ecdsa::VerifyingKey;
    type Hasher = sha2::Sha256;

    type IssuerPayloadClaims = ProtonMeetClaims;
    type KbtPayloadClaims = UserAsserted;
    type IssuerProtectedClaims = NoClaims;
    type IssuerUnprotectedClaims = NoClaims;
    type KbtUnprotectedClaims = NoClaims;
    type KbtProtectedClaims = NoClaims;

    fn new(signing_key: Self::Signer) -> Self {
        Self {
            verifying_key: *signing_key.as_ref(),
            signing_key,
        }
    }

    fn signer(&self) -> &Self::Signer {
        &self.signing_key
    }

    fn verifier(&self) -> &Self::Verifier {
        &self.verifying_key
    }

    fn cwt_algorithm(&self) -> coset::iana::Algorithm {
        coset::iana::Algorithm::ES384
    }
}
