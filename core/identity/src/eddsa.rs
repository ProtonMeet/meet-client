use crate::IdentityError;
use proton_claims::{
    ProtonMeetClaims, UserAsserted,
    reexports::{
        Holder, Verifier,
        spec::{NoClaims, reexports::coset},
    },
};

#[derive(Debug)]
pub struct ProtonEd25519SdCwtHolder {
    signing_key: ed25519_dalek::SigningKey,
    verifying_key: ed25519_dalek::VerifyingKey,
}

impl TryFrom<&[u8]> for ProtonEd25519SdCwtHolder {
    type Error = IdentityError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let bytes = bytes.try_into().map_err(signature::Error::from_source)?;
        let signing_key = ed25519_dalek::SigningKey::from_keypair_bytes(bytes)?;
        Ok(Self {
            verifying_key: signing_key.verifying_key(),
            signing_key,
        })
    }
}

impl signature::Signer<ed25519_dalek::Signature> for ProtonEd25519SdCwtHolder {
    fn try_sign(&self, msg: &[u8]) -> Result<ed25519_dalek::Signature, signature::Error> {
        self.signing_key.try_sign(msg)
    }
}

impl Holder for ProtonEd25519SdCwtHolder {
    type Error = IdentityError;
    type Signature = ed25519_dalek::Signature;
    type Signer = ed25519_dalek::SigningKey;
    type Verifier = ed25519_dalek::VerifyingKey;

    type Hasher = sha2::Sha256;

    type IssuerPayloadClaims = ProtonMeetClaims;
    type KbtPayloadClaims = UserAsserted;
    type IssuerProtectedClaims = NoClaims;
    type IssuerUnprotectedClaims = NoClaims;
    type KbtUnprotectedClaims = NoClaims;
    type KbtProtectedClaims = NoClaims;

    fn new(signing_key: Self::Signer) -> Self {
        Self {
            verifying_key: signing_key.verifying_key(),
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
        coset::iana::Algorithm::EdDSA
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct ProtonEd25519SdCwtVerifier;

impl Verifier for ProtonEd25519SdCwtVerifier {
    type Error = IdentityError;
    type HolderSignature = ed25519_dalek::Signature;
    type HolderVerifier = ed25519_dalek::VerifyingKey;

    type IssuerPayloadClaims = ProtonMeetClaims;
    type KbtPayloadClaims = UserAsserted;
    type IssuerProtectedClaims = NoClaims;
    type IssuerUnprotectedClaims = NoClaims;
    type KbtUnprotectedClaims = NoClaims;
    type KbtProtectedClaims = NoClaims;
}
