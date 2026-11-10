use proton_claims::{
    ProtonMeetClaims,
    reexports::{Issuer, NoClaims, SdHashAlg, coset},
};

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
