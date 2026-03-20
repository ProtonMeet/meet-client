pub use ecdsa::{ProtonP256SdCwtHolder, ProtonP384SdCwtHolder};
pub use eddsa::{ProtonEd25519SdCwtHolder, ProtonEd25519SdCwtVerifier};
pub use error::{IdentityError, IdentityResult};
#[cfg(feature = "test-utils")]
pub use mock_issuer::*;
pub use presentation::{Disclosure, PresentationContext, new_identity_presentation, verify_sd_cwt};
pub use read::{ProtonMeetIdentity, ProtonMeetUserAssertedIdentity};

use proton_claims::{
    ProtonMeetClaims, UserAsserted,
    reexports::{
        SdCwtVerified, Select, SpiceOidcClaims,
        spec::{issuance::SdCwtIssuedTagged, key_binding::KbtCwtTagged, verified::KbtCwtVerified},
    },
};

mod ecdsa;
mod eddsa;
mod error;
pub mod external;
pub mod mls;
#[cfg(feature = "test-utils")]
mod mock_issuer;
mod presentation;
mod read;

#[cfg(not(any(test, feature = "test-utils")))]
pub const SD_CWT_LEEWAY: std::time::Duration = std::time::Duration::from_secs(60); // between server & the client
#[cfg(not(any(test, feature = "test-utils")))]
pub const SD_KBT_LEEWAY: std::time::Duration = std::time::Duration::from_secs(60 * 5); // 5 minutes in case users turn off their mobile time sync

#[cfg(any(test, feature = "test-utils"))]
pub const SD_CWT_LEEWAY: std::time::Duration = std::time::Duration::from_secs(0);
#[cfg(any(test, feature = "test-utils"))]
pub const SD_KBT_LEEWAY: std::time::Duration = std::time::Duration::from_secs(0);

// TODO: generalize hasher later
pub type SdCwt = SdCwtIssuedTagged<ProtonMeetClaims, sha2::Sha256>;

// TODO: generalize hasher later
pub type VerifiedSdCwt = SdCwtVerified<ProtonMeetClaims, sha2::Sha256>;

// TODO: generalize hasher later
pub type SdKbt = KbtCwtTagged<ProtonMeetClaims, sha2::Sha256, UserAsserted>;

pub type SdKbtVerified = KbtCwtVerified<ProtonMeetClaims, UserAsserted>;

/// The payload of the SD-KBT of an external sender
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ExternalSenderClaims(SpiceOidcClaims);

impl Select for ExternalSenderClaims {}

pub type ExternalSenderSdKbt = KbtCwtTagged<ExternalSenderClaims, sha2::Sha256>;

/// Supported signing algorithms
#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    Ed25519,
    P256,
    P384,
}

/// Supported hash algorithms
#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
pub enum HashAlgorithm {
    SHA256,
    SHA384,
}
