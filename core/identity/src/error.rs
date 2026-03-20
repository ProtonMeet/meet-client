use proton_claims::{ProtonClaimsError, reexports::ciborium};

pub type IdentityResult<T> = Result<T, IdentityError>;

#[derive(thiserror::Error, Debug)]
pub enum IdentityError {
    #[error("{0}")]
    SdCwtReadError(String),
    #[error(transparent)]
    IdentifierError(#[from] meet_identifiers::ProtonMeetIdError),
    #[error(transparent)]
    ArrayError(#[from] std::array::TryFromSliceError),
    #[error("{0}")]
    SdCwtSpecError(String),
    #[error("{0}")]
    SdCwtHolderError(String),
    #[error("{0}")]
    SignatureError(String),
    #[error("Missing SD-CWT claim '{0}'")]
    MissingClaim(String),
    #[error("{0}")]
    ImplementationError(&'static str),
    #[error(transparent)]
    CborError(#[from] ciborium::value::Error),
    #[error(transparent)]
    ProtonClaimsError(#[from] ProtonClaimsError),
    #[error(transparent)]
    SpkiError(#[from] ed25519_dalek::pkcs8::spki::Error),
}

impl From<signature::Error> for IdentityError {
    fn from(e: signature::Error) -> Self {
        Self::SignatureError(format!("{e:?}"))
    }
}

impl From<proton_claims::reexports::spec::EsdicawtSpecError> for IdentityError {
    fn from(e: proton_claims::reexports::spec::EsdicawtSpecError) -> Self {
        Self::SdCwtSpecError(format!("{e:?}"))
    }
}

impl From<proton_claims::reexports::EsdicawtReadError> for IdentityError {
    fn from(e: proton_claims::reexports::EsdicawtReadError) -> Self {
        Self::SdCwtReadError(format!("{e:?}"))
    }
}

impl<E: std::error::Error + Send + Sync> From<proton_claims::reexports::SdCwtHolderError<E>> for IdentityError {
    fn from(e: proton_claims::reexports::SdCwtHolderError<E>) -> Self {
        Self::SdCwtHolderError(format!("{e:?}"))
    }
}
