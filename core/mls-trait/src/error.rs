use crate::{
    mimi_room_policy::spec::rbac::StdCapability, mls_spec::drafts::mls_extensions::safe_application::ComponentId,
};
use meet_identifiers::{LeafIndex, UserId};

pub type MlsResult<T> = Result<T, MlsError>;

#[derive(thiserror::Error, Debug)]
pub enum MlsError {
    #[error("Welcome KeyPackage Not Found")]
    WelcomeKeyPackageNotFound,
    #[cfg(feature = "wickr")]
    #[error(transparent)]
    WickrError(mls_rs::client::MlsError),
    #[error(transparent)]
    MeetMlsError(#[from] meet_mls::MeetMlsError),
    #[error(transparent)]
    TlsError(#[from] crate::tls_codec::Error),
    #[error(transparent)]
    SdCwtReadError(#[from] proton_claims::reexports::EsdicawtReadError),
    #[error(transparent)]
    SdCwtVerifierError(#[from] proton_claims::reexports::SdCwtVerifierError<identity::IdentityError>),
    #[cfg(feature = "wickr")]
    #[error(transparent)]
    WickrProviderError(#[from] crate::wickr::error::WickrProviderError),
    #[cfg(feature = "wickr")]
    #[error("{0}")]
    WickrAnyError(String),
    #[error("Trying to encrypt a message with inflight pending proposals")]
    CommitRequired,
    #[error(transparent)]
    MlsTypesError(#[from] mls_types::MlsTypesError),
    #[error(transparent)]
    IdentifierError(#[from] meet_identifiers::ProtonMeetIdError),
    #[error(transparent)]
    IdentityError(identity::IdentityError),
    #[error(transparent)]
    MlsEncodingError(#[from] mls_rs_codec::Error),
    #[error(transparent)]
    MlsExtensionError(#[from] mls_rs_core::extension::ExtensionError),
    #[error(transparent)]
    Rfc8747Error(#[from] proton_claims::reexports::cose_key_confirmation::error::CoseKeyConfirmationError),
    #[error(transparent)]
    MlsStorageError(#[from] crate::KvError),
    #[error(transparent)]
    CryptoError(#[from] mls_rs_crypto_rustcrypto::RustCryptoError),
    #[error("{0}")]
    ImplementationError(&'static str),
    #[error("Could not find member at index {0}")]
    MemberNotFound(LeafIndex),
    #[error("Could not find external sender at index {0}")]
    ExternalSenderNotFound(u32),
    #[error("External sender with credential type {0} is currently not supported")]
    UnsupportedExternalSenderCredential(u16),
    #[error("Could not find member index for {0:?}")]
    MemberIndexNotFound(Option<UserId>),
    #[error(transparent)]
    SdCwtSpecError(#[from] proton_claims::reexports::EsdicawtSpecError),
    #[error("{0}")]
    SdCwtHolderError(String),
    #[error(transparent)]
    EllipticCurveError(#[from] ed25519_dalek::ed25519::Error),
    #[error(transparent)]
    TryFromSliceError(#[from] std::array::TryFromSliceError),
    #[error(transparent)]
    PemError(#[from] p256::pkcs8::spki::Error),
    #[error(transparent)]
    MimiPolicyError(#[from] crate::mimi_room_policy::MimiPolicyError),
    #[error(transparent)]
    Base64DecideError(#[from] base64::DecodeError),
    #[error(transparent)]
    MlsSpecError(#[from] crate::mimi_protocol_mls::reexports::mls_spec::MlsSpecError),
    #[error("Expected GroupInfo")]
    GroupInfoExpected,
    #[error("Group has no associated RoomMetadata component")]
    MissingRoomMetadata,
    #[error("ExternalSender is invalid")]
    InvalidExternalSender,
    #[error("Lacks support for component {0} required by group")]
    MissingRequiredComponent(ComponentId),
    #[error("Lacks support for components {0:?} required by group")]
    MissingRequiredComponents(Vec<ComponentId>),
    #[error("Not all the members of the group support the component {0}")]
    UnsupportedComponent(ComponentId),
    #[error("The member to-be-added is expired")]
    NewMemberExpired,
    #[error("The member to-be-added is not yet valid")]
    NewMemberNotYetValid,
    #[error("Invalid Group member")]
    InvalidMember,
    #[error("Forbidden SignatureKey change")]
    SignatureKeyChanged,
    #[error("The member credential is expired")]
    CredentialExpired,
    #[error("The credential type is not supported")]
    UnsupportedCredentialType,
    #[error("All credentials must have a 'sub' claim to be identifiable")]
    UnidentifiableCredential,
    #[error(transparent)]
    SuccessorError(#[from] SuccessorError),
    #[error("Unauthorized capability {0:?}")]
    UnauthorizedCapability(StdCapability),
    // For variants not implementing Clone
    #[error("{0}")]
    InternalError(String),
}

#[derive(thiserror::Error, Debug)]
pub enum SuccessorError {
    #[error("Sub claim must be immutable")]
    DifferentSub,
    #[error("Holder confirmation key is immutable")]
    DifferentConfirmationKey,
}

impl From<identity::IdentityError> for MlsError {
    fn from(e: identity::IdentityError) -> Self {
        match e {
            identity::IdentityError::SdCwtHolderError(msg) if &msg == "TimeError(Expired)" => Self::CredentialExpired,
            _ => Self::IdentityError(e),
        }
    }
}

impl From<mls_rs::client::MlsError> for MlsError {
    fn from(e: mls_rs::client::MlsError) -> Self {
        match e {
            mls_rs::client::MlsError::WelcomeKeyPackageNotFound => Self::WelcomeKeyPackageNotFound,
            mls_rs::client::MlsError::CommitRequired => Self::CommitRequired,
            mls_rs::client::MlsError::IdentityProviderError(e) if &e.to_string() == "NewMemberExpired" => {
                Self::NewMemberExpired
            }
            mls_rs::client::MlsError::MlsRulesError(e)
                if &e.to_string() == "SdCwtVerifierError(TimeError(Expired))" =>
            {
                Self::NewMemberExpired
            }
            e => Self::WickrError(e),
        }
    }
}

#[cfg(feature = "wickr")]
impl From<mls_rs_core::error::AnyError> for MlsError {
    fn from(e: mls_rs_core::error::AnyError) -> Self {
        Self::WickrAnyError(e.to_string())
    }
}

impl From<crate::mimi_room_policy::authorizer::AuthorizerError> for MlsError {
    fn from(value: crate::mimi_room_policy::authorizer::AuthorizerError) -> Self {
        Self::MimiPolicyError(value.into())
    }
}

impl<E: std::error::Error + Send + Sync> From<proton_claims::reexports::SdCwtHolderError<E>> for MlsError {
    fn from(e: proton_claims::reexports::SdCwtHolderError<E>) -> Self {
        Self::SdCwtHolderError(format!("{e:?}"))
    }
}

impl mls_rs::error::IntoAnyError for MlsError {}
