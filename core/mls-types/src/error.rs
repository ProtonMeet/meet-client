pub type MlsTypesResult<T> = Result<T, MlsTypesError>;

#[derive(Debug, thiserror::Error)]
pub enum MlsTypesError {
    #[cfg(feature = "wickr")]
    #[error("{0}")]
    WickrConversionError(&'static str),
    #[cfg(feature = "wickr")]
    #[error(transparent)]
    WickrExtensionError(#[from] mls_rs::error::ExtensionError),
    #[error(transparent)]
    IdentifierError(#[from] meet_identifiers::ProtonMeetIdError),
    #[error(transparent)]
    Utf8Error(#[from] std::str::Utf8Error),
    #[error(transparent)]
    Utf8OwnedError(#[from] std::string::FromUtf8Error),
    #[error(transparent)]
    MlsRsCodecError(#[from] mls_rs_codec::Error),
    #[error(transparent)]
    TlsCodecError(#[from] crate::mls_spec::reexports::tls_codec::Error),
    #[error(transparent)]
    MlsSpecError(#[from] crate::mls_spec::MlsSpecError),
    #[error(transparent)]
    IdentityError(#[from] identity::IdentityError),
    #[error(transparent)]
    MlsClientError(#[from] mls_rs::client::MlsError),
    #[error(transparent)]
    ArraySizeError(#[from] std::array::TryFromSliceError),
    #[error(transparent)]
    SdCwtSpecError(#[from] proton_claims::reexports::EsdicawtSpecError),
    #[error(transparent)]
    SdCwtVerifierError(#[from] proton_claims::reexports::SdCwtVerifierError<core::convert::Infallible>),
    #[error("The message does not contain the expected FrankAAD component within its SafeAAD")]
    MissingFrankAad,
    #[error("The message does not contain the expected MessageIdInAad component within its SafeAAD")]
    MissingMessageIdAad,
    #[error("{0}")]
    SdCwtHolderError(String),
    #[error("{0}")]
    ImplementationError(&'static str),
    #[error("{0}")]
    InvalidMlsMessage(&'static str),
    #[error("{0} is not a supported Hash Algorithm")]
    InvalidHashAlgorithm(u8),
}

impl<E: std::error::Error + Send + Sync> From<proton_claims::reexports::SdCwtHolderError<E>> for MlsTypesError {
    fn from(e: proton_claims::reexports::SdCwtHolderError<E>) -> Self {
        Self::SdCwtHolderError(format!("{e:?}"))
    }
}
