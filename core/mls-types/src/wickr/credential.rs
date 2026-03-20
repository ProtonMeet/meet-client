use crate::{Credential, MlsTypesError, mls_spec, types::credential::CredentialExt};
use identity::SdKbt;
use mls_rs::identity::{Credential as WickrCredential, CustomCredential};
use proton_claims::reexports::{ClaimSetExt, CwtAny};

impl TryFrom<WickrCredential> for Credential {
    type Error = MlsTypesError;

    fn try_from(c: WickrCredential) -> Result<Self, Self::Error> {
        Ok(match c {
            #[cfg(any(test, feature = "test-utils"))]
            WickrCredential::Basic(b) => Self::Basic(b),
            #[cfg(any(test, feature = "test-utils"))]
            WickrCredential::X509(x) => Self::X509(x),
            WickrCredential::Custom(mls_rs::identity::CustomCredential {
                credential_type,
                data: raw_sd_kbt,
            }) if credential_type == mls_spec::defs::CredentialType::SD_CWT_CREDENTIAL.into() => {
                let mut sd_kbt = SdKbt::from_cbor_bytes(&raw_sd_kbt)?;
                Self::SdCwtDraft04 {
                    claimset: sd_kbt.0.claimset_unchecked()?,
                    sd_kbt: Box::new(sd_kbt),
                    raw_sd_kbt,
                }
            }
            _ => return Err(MlsTypesError::WickrConversionError("Unknown or unsupported credential")),
        })
    }
}

impl TryFrom<Credential> for WickrCredential {
    type Error = MlsTypesError;

    fn try_from(c: Credential) -> Result<Self, Self::Error> {
        Ok(match c {
            #[cfg(any(test, feature = "test-utils"))]
            Credential::Basic(b) => Self::Basic(b),
            #[cfg(any(test, feature = "test-utils"))]
            Credential::X509(x) => Self::X509(x),
            Credential::SdCwtDraft04 { raw_sd_kbt: data, .. } => Self::Custom(mls_rs::identity::CustomCredential {
                credential_type: mls_spec::defs::CredentialType::SD_CWT_CREDENTIAL.into(),
                data,
            }),
        })
    }
}

impl CredentialExt for WickrCredential {
    fn as_sd_cwt(&self) -> Option<&[u8]> {
        match self {
            Self::Custom(CustomCredential { credential_type, data })
                if *credential_type == mls_spec::defs::CredentialType::SD_CWT_CREDENTIAL.into() =>
            {
                Some(data)
            }
            _ => None,
        }
    }
}
