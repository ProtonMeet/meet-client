use crate::MlsResult;
#[cfg(any(test, feature = "test-utils"))]
use crate::meet_policy::RoomKind;
use crate::meet_policy::RoomPolicies;
use crate::mimi_protocol_mls::{
    components::metadata::RoomMetadata,
    reexports::{
        mls_spec::{
            self,
            drafts::mls_extensions::safe_application::{AppComponents, SafeAadComponent, WireFormats},
            group::ExternalSender,
        },
        tls_codec::Serialize,
    },
};
use meet_identifiers::RoomId;
use mls_rs::extension::ExtensionType;
use mls_rs_core::{extension::MlsExtension, identity::SigningIdentity};
use mls_spec::drafts::mls_extensions;
use mls_types::AppDataDictionaryExt;
use mls_types::{CipherSuite, CredentialType, MediaTypeList, ProtocolVersion};

/// Configuration of an MLS Client
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MlsClientConfig {
    pub ciphersuite: CipherSuite,
    pub protocol_version: ProtocolVersion,
    pub supported_media_types: MediaTypeList,
    pub supported_protocol_versions: Vec<ProtocolVersion>,
    pub supported_extensions: Vec<mls_spec::defs::ExtensionType>,
    pub supported_proposals: Vec<mls_spec::defs::ProposalType>,
    pub supported_credential_types: Vec<CredentialType>,
    pub supported_wire_formats: Vec<mls_spec::defs::WireFormat>,
    pub supported_app_components: AppComponents,
    pub supported_safe_aad_components: SafeAadComponent,
}

impl MlsClientConfig {
    fn app_data(&self) -> MlsResult<mls_extensions::safe_application::ApplicationDataDictionary> {
        let mut app_data = mls_extensions::safe_application::ApplicationDataDictionary::default();
        app_data.insert_or_update_component(&self.supported_app_components)?;
        app_data.insert_or_update_component(&self.supported_safe_aad_components)?;
        app_data.insert_or_update_component(&self.supported_media_types)?;
        Ok(app_data)
    }
}

#[cfg(feature = "wickr")]
impl MlsClientConfig {
    pub fn supported_extensions(&self) -> Vec<ExtensionType> {
        self.supported_extensions
            .iter()
            .map(std::ops::Deref::deref)
            .map(|e| ExtensionType::new(*e))
            .collect()
    }

    pub fn supported_proposal_type(&self) -> Vec<mls_rs_core::group::ProposalType> {
        self.supported_proposals
            .iter()
            .map(std::ops::Deref::deref)
            .map(|p| mls_rs_core::group::ProposalType::new(*p))
            .collect()
    }

    pub fn supported_protocol_versions(&self) -> Vec<mls_rs_core::protocol_version::ProtocolVersion> {
        self.supported_protocol_versions
            .iter()
            .copied()
            .map(Into::into)
            .collect()
    }

    pub fn supported_credential_types(&self) -> Vec<mls_rs_core::identity::CredentialType> {
        self.supported_credential_types
            .iter()
            .copied()
            .map(Into::into)
            .collect()
    }

    fn supported_wire_formats(&self) -> MlsResult<mls_rs::Extension> {
        Ok(mls_rs::Extension::new(
            ExtensionType::new(mls_extensions::EXTENSION_SUPPORTED_WIRE_FORMATS),
            WireFormats {
                wire_formats: self.supported_wire_formats.clone(),
            }
            .tls_serialize_detached()?,
        ))
    }

    pub fn key_package_extensions(&self) -> MlsResult<mls_rs_core::extension::ExtensionList> {
        // nothing to add in KeyPackage extensions for the moment
        Ok(mls_rs_core::extension::ExtensionList::new())
    }

    pub fn leaf_node_extensions(&self) -> MlsResult<mls_rs_core::extension::ExtensionList> {
        let app_data = self.app_data()?.to_mls_rs_extension()?;
        let supported_wire_formats = self.supported_wire_formats()?;
        Ok(mls_rs_core::extension::ExtensionList::from_iter([
            app_data,
            supported_wire_formats,
        ]))
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl Default for MlsClientConfig {
    fn default() -> Self {
        use meet_mls::reexports::mimi_protocol_mls::{
            ParticipantListData,
            reexports::mls_spec::drafts::mls_extensions::safe_application::{Component, ComponentsList},
        };
        use meet_mls::reexports::mimi_room_policy::spec::{preauth::PreAuthData, rbac::RoleData};
        use mls_spec::defs::{ExtensionType, ProposalType};
        use mls_types::{MediaType, MediaTypeParameter};

        Self {
            ciphersuite: CipherSuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            protocol_version: ProtocolVersion::MLS10,
            supported_media_types: vec![
                MediaType {
                    media_type: "text/plain".into(),
                    parameters: vec![MediaTypeParameter {
                        name: "charset".into(),
                        value: "UTF-8".into(),
                    }],
                },
                MediaType {
                    media_type: "text/plain".into(),
                    parameters: vec![],
                },
                MediaType {
                    media_type: "application/mimi-content".into(),
                    parameters: vec![],
                },
                MediaType {
                    media_type: "image/png".into(),
                    parameters: vec![],
                },
                MediaType {
                    media_type: "image/jpeg".into(),
                    parameters: vec![],
                },
                MediaType {
                    media_type: "video/mp4".into(),
                    parameters: vec![],
                },
            ]
            .into(),
            supported_protocol_versions: vec![ProtocolVersion::MLS10],
            supported_extensions: vec![
                ExtensionType::new_unchecked(ExtensionType::APPLICATION_DATA_DICTIONARY),
                ExtensionType::new_unchecked(ExtensionType::SUPPORTED_WIRE_FORMATS),
                ExtensionType::new_unchecked(ExtensionType::REQUIRED_WIRE_FORMATS),
            ],
            supported_proposals: vec![
                ProposalType::new_unchecked(ProposalType::APP_DATA_UPDATE),
                ProposalType::new_unchecked(ProposalType::APP_EPHEMERAL),
            ],
            supported_credential_types: vec![CredentialType::SdCwtDraft04],
            supported_wire_formats: vec![],
            supported_app_components: AppComponents(ComponentsList {
                component_ids: vec![
                    AppComponents::component_id(),
                    SafeAadComponent::component_id(),
                    MediaTypeList::component_id(),
                    RoomMetadata::component_id(),
                    RoleData::component_id(),
                    ParticipantListData::component_id(),
                    PreAuthData::component_id(),
                ],
            }),
            supported_safe_aad_components: SafeAadComponent(ComponentsList { component_ids: vec![] }),
        }
    }
}

/// Configuration of an MLS Group
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum MlsGroupConfig {
    Regular { common: CommonMlsGroupConfig },
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CommonMlsGroupConfig {
    pub required_media_types: MediaTypeList,
    pub required_extensions: Vec<mls_spec::defs::ExtensionType>,
    pub required_proposals: Vec<mls_spec::defs::ProposalType>,
    pub required_credential_types: Vec<CredentialType>,
    pub required_app_components: AppComponents,
    pub required_safe_aad_components: SafeAadComponent,
    pub required_wire_formats: Vec<mls_spec::defs::WireFormat>,
    pub policies: RoomPolicies,
    pub room_metadata: RoomMetadata,
    pub external_senders: Vec<ExternalSender>,
}

impl MlsGroupConfig {
    fn app_data(&self) -> MlsResult<mls_extensions::safe_application::ApplicationDataDictionary> {
        let mut app_data = mls_extensions::safe_application::ApplicationDataDictionary::default();

        app_data.insert_or_update_component(&self.required_app_components)?;
        app_data.insert_or_update_component(&self.required_safe_aad_components)?;
        app_data.insert_or_update_component(&self.required_media_types)?;
        app_data.insert_or_update_component(&self.room_metadata)?;
        app_data.insert_or_update_component(&self.policies.roles)?;
        app_data.insert_or_update_component(&self.policies.pre_auth)?;
        app_data.insert_or_update_component(&self.policies.participant_list)?;
        Ok(app_data)
    }

    pub fn room_id(&self) -> MlsResult<RoomId> {
        Ok(self.room_metadata.room_uri.uri.parse()?)
    }
}

impl std::ops::Deref for MlsGroupConfig {
    type Target = CommonMlsGroupConfig;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Regular { common } => common,
        }
    }
}

impl std::ops::DerefMut for MlsGroupConfig {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Regular { common } => common,
        }
    }
}

#[cfg(feature = "wickr")]
impl MlsGroupConfig {
    pub fn group_context_extensions(self) -> MlsResult<mls_rs_core::extension::ExtensionList> {
        let app_data = self.app_data()?.to_mls_rs_extension()?;
        let required_capabilities = self.required_capabilities().into_extension()?;
        let required_wire_formats = self.required_wire_formats()?;
        let external_senders = self.external_senders()?.into_extension()?;
        Ok(mls_rs_core::extension::ExtensionList::from_iter([
            app_data,
            required_capabilities,
            required_wire_formats,
            external_senders,
        ]))
    }

    fn required_capabilities(&self) -> mls_rs::extension::built_in::RequiredCapabilitiesExt {
        mls_rs::extension::built_in::RequiredCapabilitiesExt::new(
            self.required_extensions(),
            self.required_proposal_type(),
            self.required_credential_types(),
        )
    }

    fn external_senders(&self) -> MlsResult<mls_rs::extension::built_in::ExternalSendersExt> {
        let signing_identities = self
            .external_senders
            .iter()
            .map(|ext_sender| {
                let credential: mls_types::Credential = ext_sender.credential.clone().try_into()?;
                let signature_pk =
                    mls_rs_core::crypto::SignaturePublicKey::new_slice(ext_sender.signature_key.as_slice());
                Ok(SigningIdentity::new(credential.try_into()?, signature_pk))
            })
            .collect::<MlsResult<_>>()?;
        Ok(mls_rs::extension::built_in::ExternalSendersExt::new(signing_identities))
    }

    fn required_extensions(&self) -> Vec<ExtensionType> {
        self.required_extensions
            .iter()
            .map(std::ops::Deref::deref)
            .map(|e| ExtensionType::new(*e))
            .collect()
    }

    fn required_proposal_type(&self) -> Vec<mls_rs_core::group::ProposalType> {
        self.required_proposals
            .iter()
            .map(std::ops::Deref::deref)
            .map(|p| mls_rs_core::group::ProposalType::new(*p))
            .collect()
    }

    fn required_credential_types(&self) -> Vec<mls_rs_core::identity::CredentialType> {
        self.required_credential_types.iter().copied().map(Into::into).collect()
    }

    fn required_wire_formats(&self) -> MlsResult<mls_rs::Extension> {
        Ok(mls_rs::Extension::new(
            ExtensionType::new(mls_extensions::EXTENSION_REQUIRED_WIRE_FORMATS),
            WireFormats {
                wire_formats: self.required_wire_formats.clone(),
            }
            .tls_serialize_detached()?,
        ))
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl MlsGroupConfig {
    pub fn default(creator: meet_identifiers::UserId, is_host: bool) -> Self {
        let room_kind = RoomKind::Room {
            is_open: true,
            other_users: vec![],
        };
        Self::new(creator, room_kind, is_host)
    }

    pub fn new(creator: meet_identifiers::UserId, room_kind: RoomKind, is_host: bool) -> Self {
        Self::new_with_cfg(creator, Self::default_room_metadata(), room_kind, is_host)
    }

    pub fn new_with_cfg(
        creator: meet_identifiers::UserId,
        room_metadata: impl Into<RoomMetadata>,
        room_kind: RoomKind,
        is_host: bool,
    ) -> Self {
        use meet_mls::reexports::mimi_protocol_mls::{
            ParticipantListData,
            reexports::mls_spec::drafts::mls_extensions::safe_application::{Component, ComponentsList},
        };
        use meet_mls::reexports::mimi_room_policy::spec::{preauth::PreAuthData, rbac::RoleData};
        use mls_spec::defs::{ExtensionType, ProposalType};
        use mls_types::{MediaType, MediaTypeParameter};

        #[allow(clippy::unwrap_used)]
        let policies = RoomPolicies::new(&creator, &room_kind, is_host).unwrap();
        let common = CommonMlsGroupConfig {
            required_media_types: vec![
                MediaType {
                    media_type: "text/plain".into(),
                    parameters: vec![MediaTypeParameter {
                        name: "charset".into(),
                        value: "UTF-8".into(),
                    }],
                },
                MediaType {
                    media_type: "image/png".into(),
                    parameters: vec![],
                },
                MediaType {
                    media_type: "image/jpeg".into(),
                    parameters: vec![],
                },
            ]
            .into(),
            required_extensions: vec![
                ExtensionType::new_unchecked(ExtensionType::APPLICATION_DATA_DICTIONARY),
                ExtensionType::new_unchecked(ExtensionType::SUPPORTED_WIRE_FORMATS),
                ExtensionType::new_unchecked(ExtensionType::REQUIRED_WIRE_FORMATS),
            ],
            required_proposals: vec![
                ProposalType::new_unchecked(ProposalType::APP_DATA_UPDATE),
                ProposalType::new_unchecked(ProposalType::APP_EPHEMERAL),
            ],
            required_credential_types: vec![CredentialType::SdCwtDraft04],
            policies,
            room_metadata: room_metadata.into(),
            required_app_components: AppComponents(ComponentsList {
                component_ids: vec![
                    AppComponents::component_id(),
                    SafeAadComponent::component_id(),
                    MediaTypeList::component_id(),
                    RoomMetadata::component_id(),
                    RoleData::component_id(),
                    ParticipantListData::component_id(),
                    PreAuthData::component_id(),
                ],
            }),
            required_safe_aad_components: SafeAadComponent(ComponentsList { component_ids: vec![] }),
            required_wire_formats: vec![],
            external_senders: vec![],
        };
        Self::Regular { common }
    }

    pub fn default_room_metadata() -> RoomMetadata {
        RoomMetadata {
            room_uri: meet_mls::reexports::mimi_protocol_mls::Uri {
                uri: RoomId::new(&meet_identifiers::Domain::default()).to_string(),
            },
            room_name: meet_mls::reexports::mimi_protocol_mls::UTF8String { string: "".into() },
            room_descriptions: vec![],
            room_avatar: meet_mls::reexports::mimi_protocol_mls::Uri { uri: "".into() },
            room_subject: meet_mls::reexports::mimi_protocol_mls::UTF8String { string: "".into() },
            room_mood: meet_mls::reexports::mimi_protocol_mls::UTF8String { string: "".into() },
        }
    }
}
