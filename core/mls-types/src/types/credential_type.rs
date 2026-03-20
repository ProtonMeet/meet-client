use crate::mls_spec;

/// MLS Credential type
/// See https://www.rfc-editor.org/rfc/rfc9420.html#name-mls-credential-types
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
#[repr(u16)]
pub enum CredentialType {
    Basic = mls_spec::defs::CredentialType::BASIC,
    X509 = mls_spec::defs::CredentialType::X509,
    SdCwtDraft04 = CredentialType::SD_CWT,
    #[cfg(any(test, feature = "test-utils"))]
    Custom = 1234,
}

impl CredentialType {
    pub const SD_CWT: u16 = mls_spec::defs::CredentialType::SD_CWT_CREDENTIAL;
}

impl std::fmt::Display for CredentialType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Basic => "Basic",
            Self::X509 => "X509",
            Self::SdCwtDraft04 => "SD-CWT-draft-04",
            #[cfg(any(test, feature = "test-utils"))]
            Self::Custom => "Custom",
        };
        write!(f, "{name}")
    }
}
