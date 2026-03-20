use crate::{CredentialType, MlsTypesError, mls_spec};

impl From<CredentialType> for mls_rs::identity::CredentialType {
    fn from(v: CredentialType) -> Self {
        match v {
            CredentialType::Basic => Self::BASIC,
            CredentialType::X509 => Self::X509,
            CredentialType::SdCwtDraft04 => Self::new(CredentialType::SD_CWT),
            #[cfg(any(test, feature = "test-utils"))]
            CredentialType::Custom => Self::new(1234),
        }
    }
}

impl TryFrom<mls_rs::identity::CredentialType> for CredentialType {
    type Error = MlsTypesError;

    fn try_from(v: mls_rs::identity::CredentialType) -> Result<Self, Self::Error> {
        match v {
            mls_rs::identity::CredentialType::BASIC => Ok(Self::Basic),
            mls_rs::identity::CredentialType::X509 => Ok(Self::X509),
            _ => match v.raw_value() {
                Self::SD_CWT => Ok(Self::SdCwtDraft04),
                #[cfg(any(test, feature = "test-utils"))]
                1234 => Ok(Self::Custom),
                _ => Err(MlsTypesError::WickrConversionError("Unknown credential type")),
            },
        }
    }
}

#[inline(always)]
pub fn mls_spec_to_mls_rs(value: mls_spec::defs::CredentialType) -> mls_rs::identity::CredentialType {
    mls_rs::identity::CredentialType::from(*value)
}
