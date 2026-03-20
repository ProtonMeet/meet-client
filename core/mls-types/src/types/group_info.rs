use crate::mls_spec;
use crate::{
    MlsTypesError, MlsTypesResult,
    mls_spec::{
        drafts::mls_extensions::safe_application::Component,
        group::{ExternalSender, extensions::Extension},
    },
    types::extensions::ExtensionListExt,
};
use meet_identifiers::{Epoch, GroupId, RoomId};
use meet_mls::reexports::{
    mimi_protocol_mls::{ParticipantListData, components::metadata::RoomMetadata},
    mimi_room_policy::spec::preauth::PreAuthData,
};
use mls_rs::{extension::built_in::ExternalSendersExt, group::GroupContext};
use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};

#[derive(Debug, Clone, MlsDecode, MlsEncode, MlsSize)]
pub struct GroupInfo(pub(crate) mls_rs::group::GroupInfo);

#[derive(Debug)]
pub struct GroupInfoRef<'g>(pub(crate) &'g mls_rs::group::GroupInfo);

pub trait GroupInfoExt {
    fn room_id(&self) -> MlsTypesResult<Option<RoomId>> {
        Ok(self
            .room_metadata()?
            .map(|meta| meta.room_uri.uri.parse())
            .transpose()?)
    }

    fn component<C: Component>(&self) -> MlsTypesResult<Option<C>>;

    fn room_metadata(&self) -> MlsTypesResult<Option<RoomMetadata>> {
        self.component()
    }

    fn preauth(&self) -> MlsTypesResult<Option<PreAuthData>> {
        self.component()
    }

    fn external_senders(&self) -> MlsTypesResult<Vec<ExternalSender>>;

    fn participants(&self) -> MlsTypesResult<Option<ParticipantListData>>;
}

impl GroupInfoExt for mls_spec::group::group_info::GroupInfo {
    fn component<C: Component>(&self) -> MlsTypesResult<Option<C>> {
        Ok(self
            .group_context
            .extensions
            .iter()
            .find_map(|e| match e {
                Extension::ApplicationData(app_data) => Some(app_data.extract_component::<C>()),
                _ => None,
            })
            .transpose()?
            .flatten())
    }

    fn external_senders(&self) -> MlsTypesResult<Vec<ExternalSender>> {
        Ok(self
            .group_context
            .extensions
            .iter()
            .find_map(|e| match e {
                Extension::ExternalSenders(s) => Some(s.clone()),
                _ => None,
            })
            .unwrap_or_default())
    }

    fn participants(&self) -> MlsTypesResult<Option<ParticipantListData>> {
        Ok(self
            .group_context
            .extensions
            .iter()
            .find_map(|e| match e {
                Extension::ApplicationData(app_data) => Some(app_data.extract_component::<ParticipantListData>()),
                _ => None,
            })
            .transpose()?
            .flatten())
    }
}

impl GroupInfoExt for GroupInfo {
    fn component<C: Component>(&self) -> MlsTypesResult<Option<C>> {
        GroupInfoRef(&self.0).component()
    }

    fn external_senders(&self) -> MlsTypesResult<Vec<ExternalSender>> {
        GroupInfoRef(&self.0).external_senders()
    }

    fn participants(&self) -> MlsTypesResult<Option<ParticipantListData>> {
        GroupInfoRef(&self.0).participants()
    }
}

impl GroupInfoExt for GroupInfoRef<'_> {
    fn component<C: Component>(&self) -> MlsTypesResult<Option<C>> {
        Ok(self
            .context()
            .extensions
            .application_data_spec()?
            .and_then(|a| a.extract_component::<C>().transpose())
            .transpose()?)
    }

    fn external_senders(&self) -> MlsTypesResult<Vec<ExternalSender>> {
        let Some(external_senders) = self.context().extensions.get_as::<ExternalSendersExt>()? else {
            return Ok(vec![]);
        };
        external_senders
            .allowed_senders
            .iter()
            .map(|s| {
                let credential = crate::Credential::try_from(s.credential.clone())?.try_into()?;
                let signature_key = s.signature_key.to_vec().into();
                Ok(ExternalSender {
                    signature_key,
                    credential,
                })
            })
            .collect::<MlsTypesResult<Vec<_>>>()
    }

    fn participants(&self) -> MlsTypesResult<Option<ParticipantListData>> {
        Ok(self
            .context()
            .extensions
            .application_data_spec()?
            .and_then(|a| a.extract_component::<ParticipantListData>().transpose())
            .transpose()?)
    }
}

impl TryFrom<mls_rs::MlsMessage> for GroupInfo {
    type Error = MlsTypesError;

    fn try_from(msg: mls_rs::MlsMessage) -> Result<Self, Self::Error> {
        let group_info = msg.into_group_info().ok_or(MlsTypesError::ImplementationError(
            "Expected a GroupInfo wrapped in a MlsMessage",
        ))?;
        Ok(Self(group_info))
    }
}

impl<'g> TryFrom<&'g mls_rs::MlsMessage> for GroupInfoRef<'g> {
    type Error = MlsTypesError;

    fn try_from(msg: &'g mls_rs::MlsMessage) -> Result<Self, Self::Error> {
        let group_info = msg.as_group_info().ok_or(MlsTypesError::ImplementationError(
            "Expected a GroupInfo wrapped in a MlsMessage",
        ))?;
        Ok(Self(group_info))
    }
}

impl From<mls_rs::group::GroupInfo> for GroupInfo {
    fn from(value: mls_rs::group::GroupInfo) -> Self {
        Self(value)
    }
}

impl<'g> From<&'g mls_rs::group::GroupInfo> for GroupInfoRef<'g> {
    fn from(value: &'g mls_rs::group::GroupInfo) -> Self {
        Self(value)
    }
}

impl GroupInfo {
    pub fn group_id(&self) -> MlsTypesResult<GroupId> {
        GroupId::try_from(self.0.group_context().group_id()).map_err(Into::into)
    }

    pub fn epoch(&self) -> Epoch {
        self.0.group_context().epoch().into()
    }
}

impl GroupInfoRef<'_> {
    pub fn group_id(&self) -> MlsTypesResult<GroupId> {
        GroupId::try_from(self.0.group_context().group_id()).map_err(Into::into)
    }

    pub fn epoch(&self) -> Epoch {
        self.context().epoch().into()
    }

    pub fn context(&self) -> &GroupContext {
        self.0.group_context()
    }
}
