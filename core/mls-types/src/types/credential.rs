use crate::{CredentialType, MlsTypesResult};
use identity::{ProtonMeetIdentity, ProtonMeetUserAssertedIdentity, SdKbt};
use meet_identifiers::{AsOwned, DeviceId, DeviceIdRef, ProtonEmail, UserId};
use proton_claims::{About, ProtonMeetClaims, Role as ProtonRole};
use url::Url;

#[derive(Clone, PartialEq)]
pub enum Credential {
    #[cfg(any(test, feature = "test-utils"))]
    Basic(mls_rs::identity::basic::BasicCredential),
    #[cfg(any(test, feature = "test-utils"))]
    X509(mls_rs::identity::x509::CertificateChain),
    SdCwtDraft04 {
        claimset: Option<ProtonMeetClaims>,
        sd_kbt: Box<SdKbt>,
        raw_sd_kbt: Vec<u8>,
    },
}

#[derive(Debug, Clone)]
pub struct CredentialClaims {
    // === SD-CWT ===
    pub device_id: DeviceId,
    // CwtOidcLabel::Name
    pub name: Option<String>,
    // CwtOidcLabel::Email
    pub email: Option<ProtonEmail>,
    // CwtOidcLabel::Picture
    pub picture: Option<Url>,
    // CwtProtonLabel::Role
    pub workspace_role: Option<ProtonRole>,
    // === User asserted ===
    /// Identity description/biography/about
    pub about: Option<About>,
    /// KBT issued at (Unix timestamp in __seconds__)
    pub kbt_issued_at: u64,
    /// CWT issued at (Unix timestamp in __seconds__)
    pub cwt_issued_at: u64,
}

impl Credential {
    pub fn device_id(&mut self) -> MlsTypesResult<DeviceId> {
        Ok(self.device_id_ref()?.as_owned())
    }

    pub fn device_id_ref(&mut self) -> MlsTypesResult<DeviceIdRef<'_>> {
        Ok(match self {
            #[cfg(any(test, feature = "test-utils"))]
            Self::Basic(b) => b.identifier.as_slice().try_into()?,
            #[cfg(any(test, feature = "test-utils"))]
            Self::X509(_) => {
                return Err(crate::MlsTypesError::ImplementationError(
                    "Extracting X509 DeviceId not yet supported",
                ));
            }
            // no need to read it from claimset as it's in the 'sub' which is not redactable so no need to hash anything to resolve it
            Self::SdCwtDraft04 { sd_kbt, .. } => sd_kbt.device_id_ref()?,
        })
    }

    pub fn user_id(&mut self) -> MlsTypesResult<UserId> {
        Ok(self.device_id()?.owning_identity_id().as_owned())
    }

    pub fn name(&mut self) -> Option<String> {
        match self {
            Self::SdCwtDraft04 {
                claimset: Some(claimset),
                ..
            } => claimset.oidc_claims.name.clone(),
            Self::SdCwtDraft04 { sd_kbt, .. } => sd_kbt.name().ok(),
            #[cfg(any(test, feature = "test-utils"))]
            Self::Basic(_) | Self::X509(_) => None,
        }
    }

    pub fn email(&mut self) -> Option<ProtonEmail> {
        match self {
            Self::SdCwtDraft04 {
                claimset: Some(claimset),
                ..
            } => claimset.oidc_claims.email.as_deref().and_then(|e| e.parse().ok()),
            Self::SdCwtDraft04 { sd_kbt, .. } => sd_kbt.email().ok(),
            #[cfg(any(test, feature = "test-utils"))]
            Self::Basic(_) | Self::X509(_) => None,
        }
    }

    pub fn picture(&mut self) -> Option<Url> {
        match self {
            Self::SdCwtDraft04 {
                claimset: Some(claimset),
                ..
            } => claimset.oidc_claims.picture.clone(),
            Self::SdCwtDraft04 { sd_kbt, .. } => sd_kbt.picture().ok(),
            #[cfg(any(test, feature = "test-utils"))]
            Self::Basic(_) | Self::X509(_) => None,
        }
    }

    /// Get the 'about' user asserted claim
    pub fn about(&mut self) -> Option<&About> {
        match self {
            Self::SdCwtDraft04 { sd_kbt, .. } => sd_kbt.about().ok().flatten(),
            #[cfg(any(test, feature = "test-utils"))]
            Self::Basic(_) | Self::X509(_) => None,
        }
    }

    #[inline]
    pub fn workspace_role(&mut self) -> Option<ProtonRole> {
        match self {
            Self::SdCwtDraft04 {
                claimset: Some(claimset),
                ..
            } => Some(claimset.role),
            Self::SdCwtDraft04 { sd_kbt, .. } => sd_kbt.workspace_role().ok(),
            #[cfg(any(test, feature = "test-utils"))]
            Self::Basic(_) | Self::X509(_) => None,
        }
    }

    #[inline]
    pub fn credential_type(&self) -> CredentialType {
        match self {
            Self::SdCwtDraft04 { .. } => CredentialType::SdCwtDraft04,
            #[cfg(any(test, feature = "test-utils"))]
            Self::Basic(_) => CredentialType::Basic,
            #[cfg(any(test, feature = "test-utils"))]
            Self::X509(_) => CredentialType::X509,
        }
    }

    /// Issuance date of the KBT as UNIX timestamp in __seconds__
    #[inline]
    pub fn kbt_issued_at(&mut self) -> MlsTypesResult<u64> {
        match self {
            Self::SdCwtDraft04 { sd_kbt, .. } => Ok(sd_kbt.kbt_iat()?),
            #[cfg(any(test, feature = "test-utils"))]
            Self::Basic(_) | Self::X509(_) => Err(crate::MlsTypesError::ImplementationError(
                "Extracting Basic/X509 issued_at not yet supported",
            )),
        }
    }

    /// Issuance date of the CWT as UNIX timestamp in __seconds__
    #[inline]
    pub fn cwt_issued_at(&mut self) -> MlsTypesResult<u64> {
        match self {
            Self::SdCwtDraft04 { sd_kbt, .. } => Ok(sd_kbt.cwt_iat()?),
            #[cfg(any(test, feature = "test-utils"))]
            Self::Basic(_) | Self::X509(_) => Err(crate::MlsTypesError::ImplementationError(
                "Extracting Basic/X509 cwt_issued_at not yet supported",
            )),
        }
    }

    pub fn claimset(&mut self) -> MlsTypesResult<CredentialClaims> {
        Ok(CredentialClaims {
            device_id: self.device_id()?,
            name: self.name(),
            email: self.email(),
            picture: self.picture(),
            workspace_role: self.workspace_role(),
            about: self.about().cloned(),
            kbt_issued_at: self.kbt_issued_at()?,
            cwt_issued_at: self.cwt_issued_at()?,
        })
    }
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let d = match self {
            #[cfg(any(test, feature = "test-utils"))]
            Self::Basic(_) => "Basic(***)",
            #[cfg(any(test, feature = "test-utils"))]
            Self::X509(_) => "X509(***)",
            Self::SdCwtDraft04 { .. } => "SdCwt-draft-04(***)",
        };
        write!(f, "{d}")
    }
}

pub trait CredentialExt {
    fn as_sd_cwt(&self) -> Option<&[u8]>;
}
