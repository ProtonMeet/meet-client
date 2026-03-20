use crate::MlsTypesError;
use crate::mls_spec;
use identity::SdKbt;
use proton_claims::reexports::{ClaimSetExt, CwtAny};

impl TryFrom<mls_spec::defs::CredentialType> for crate::CredentialType {
    type Error = MlsTypesError;

    fn try_from(value: mls_spec::defs::CredentialType) -> Result<Self, Self::Error> {
        Ok(match *value {
            #[cfg(any(test, feature = "test-utils"))]
            mls_spec::defs::CredentialType::BASIC => Self::Basic,
            #[cfg(any(test, feature = "test-utils"))]
            mls_spec::defs::CredentialType::X509 => Self::X509,
            mls_spec::defs::CredentialType::SD_CWT_CREDENTIAL => Self::SdCwtDraft04,
            _ => return Err(Self::Error::ImplementationError("Unknown credential type")),
        })
    }
}

impl From<crate::CredentialType> for mls_spec::defs::CredentialType {
    fn from(value: crate::CredentialType) -> Self {
        Self::new_unchecked(value as u16)
    }
}

impl TryFrom<mls_spec::credential::Credential> for crate::Credential {
    type Error = MlsTypesError;

    fn try_from(c: mls_spec::credential::Credential) -> Result<Self, Self::Error> {
        Ok(match c {
            #[cfg(any(test, feature = "test-utils"))]
            mls_spec::credential::Credential::Basic(b) => {
                Self::Basic(mls_rs::identity::basic::BasicCredential::new(b.identity))
            }
            mls_spec::credential::Credential::SdCwtCredential(raw) => {
                let mut sd_kbt = SdKbt::from_cbor_bytes(&raw.sd_kbt)?;
                Self::SdCwtDraft04 {
                    claimset: sd_kbt.0.claimset_unchecked()?,
                    raw_sd_kbt: raw.sd_kbt,
                    sd_kbt: Box::new(sd_kbt),
                }
            }
            _ => return Err(MlsTypesError::ImplementationError("Unsupported credential type")),
        })
    }
}

impl TryFrom<crate::Credential> for mls_spec::credential::Credential {
    type Error = MlsTypesError;

    fn try_from(c: crate::Credential) -> Result<Self, Self::Error> {
        Ok(match c {
            #[cfg(any(test, feature = "test-utils"))]
            crate::Credential::Basic(b) => {
                Self::Basic(mls_spec::credential::BasicCredential { identity: b.identifier })
            }
            crate::Credential::SdCwtDraft04 { raw_sd_kbt, .. } => {
                Self::SdCwtCredential(mls_spec::drafts::sd_cwt_credential::SdCwtCredential { sd_kbt: raw_sd_kbt })
            }
            #[cfg(any(test, feature = "test-utils"))]
            _ => return Err(MlsTypesError::ImplementationError("Unsupported credential type")),
        })
    }
}
