use crate::mimi_protocol_mls::reexports::tls_codec;

use crate::kv::KvError;

use super::rules::ProposalValidationError;

#[derive(Debug, thiserror::Error)]
pub enum WickrProviderError {
    #[error(transparent)]
    Infallible(#[from] core::convert::Infallible),
    #[error(transparent)]
    RustCryptoError(#[from] mls_rs_crypto_rustcrypto::RustCryptoError),
    #[error(transparent)]
    KvError(#[from] KvError),
    #[error(transparent)]
    CommonError(#[from] meet_identifiers::ProtonMeetIdError),
    #[error("unauthorized")]
    Unauthorized,
    #[error(transparent)]
    Tls(#[from] tls_codec::Error),
    #[error(transparent)]
    Proposal(#[from] ProposalValidationError),
}

impl mls_rs::error::IntoAnyError for WickrProviderError {}
