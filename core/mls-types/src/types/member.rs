use crate::{
    Capabilities, Credential, CredentialType, Extensions, MlsTypesResult,
    mls_spec::drafts::mls_extensions::safe_application::ApplicationDataDictionary,
};
use meet_identifiers::{DeviceId, DeviceIdRef, LeafIndex, ProtonEmail, UserId};
use proton_claims::Role as ProtonRole;
use url::Url;

/// Mls group member device
#[derive(Debug, Clone, PartialEq)]
pub struct Member {
    pub leaf_index: LeafIndex,
    pub credential: Credential,
    pub extensions: Extensions,
    pub capabilities: Capabilities,
}

impl Member {
    pub fn new(
        credential: Credential,
        leaf_index: LeafIndex,
        extensions: Extensions,
        capabilities: Capabilities,
    ) -> Self {
        Self {
            leaf_index,
            credential,
            extensions,
            capabilities,
        }
    }

    #[inline]
    #[must_use]
    pub fn name(&mut self) -> Option<String> {
        self.credential.name()
    }

    #[inline]
    #[must_use]
    pub const fn leaf_index(&self) -> LeafIndex {
        self.leaf_index
    }

    #[inline]
    pub fn user_id(&mut self) -> MlsTypesResult<UserId> {
        self.credential.user_id()
    }

    #[inline]
    pub fn device_id(&mut self) -> MlsTypesResult<DeviceId> {
        self.credential.device_id()
    }

    #[inline]
    pub fn device_id_ref(&mut self) -> MlsTypesResult<DeviceIdRef<'_>> {
        self.credential.device_id_ref()
    }

    #[inline]
    pub fn email(&mut self) -> Option<ProtonEmail> {
        self.credential.email()
    }

    #[inline]
    pub fn picture(&mut self) -> Option<Url> {
        self.credential.picture()
    }

    #[inline]
    pub fn workspace_role(&mut self) -> ProtonRole {
        self.credential.workspace_role().unwrap_or_default()
    }

    #[inline]
    #[must_use]
    pub fn credential(&self) -> &Credential {
        &self.credential
    }

    #[inline]
    pub fn credential_type(&self) -> CredentialType {
        self.credential.credential_type()
    }

    #[inline]
    #[must_use]
    pub fn into_credential(self) -> Credential {
        self.credential
    }

    fn application_data(&self) -> Option<&ApplicationDataDictionary> {
        self.extensions.0.iter().find_map(|e| match e {
            crate::mls_spec::group::extensions::Extension::ApplicationData(app_data) => Some(app_data),
            _ => None,
        })
    }
}
