use base64::Engine;
use meet_identifiers::{Domain, ProtonEmail};
use proton_claims::{
    ProtonMeetClaims,
    reexports::{Issuer, NoClaims, SdHashAlg, coset},
};
use sha2::Digest;

/// This will generate a valid id part of a mimi url that has the correct amont of bytes
fn generate_id(string: &str) -> String {
    #[allow(clippy::indexing_slicing)] // SAFETY: SHA-256 output is always 32 bytes so slicing is safe
    let digest = &sha2::Sha256::digest(string.as_bytes())[..16];
    base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(digest)
}

fn generate_device_id(holder_confirmation_key_pem: &str) -> String {
    generate_id(holder_confirmation_key_pem)
}

fn generate_user_id(email: &ProtonEmail) -> String {
    generate_id(email)
}

fn generate_mimi_subject(domain: &Domain, email: &ProtonEmail, holder_confirmation_key_pem: &str) -> String {
    let user_id = generate_user_id(email);
    let device_id = generate_device_id(holder_confirmation_key_pem);
    format!("mimi://{domain}/d/{user_id}/{device_id}")
}

pub struct Ed25519Issuer {
    signing_key: ed25519_dalek::SigningKey,
}

impl Issuer for Ed25519Issuer {
    type Error = std::convert::Infallible;
    type Signature = ed25519_dalek::Signature;
    type Signer = ed25519_dalek::SigningKey;
    type Hasher = sha2::Sha256;

    type PayloadClaims = ProtonMeetClaims;
    type ProtectedClaims = NoClaims;
    type UnprotectedClaims = NoClaims;

    fn new(signing_key: Self::Signer) -> Self {
        Self { signing_key }
    }

    fn signer(&self) -> &Self::Signer {
        &self.signing_key
    }

    fn cwt_algorithm(&self) -> coset::iana::Algorithm {
        coset::iana::Algorithm::EdDSA
    }

    fn hash_algorithm(&self) -> SdHashAlg {
        SdHashAlg::Sha256
    }
}
