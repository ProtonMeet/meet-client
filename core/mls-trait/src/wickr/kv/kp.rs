use crate::{KvExt, MlsError, MlsResult, kv::MlsEntity, wickr::error::WickrProviderError};
use base64::Engine;
use mls_rs::KeyPackageRef as WickrKeyPackageRef;
use mls_rs_core::key_package::KeyPackageData as WickrKeyPackage;
use mls_types::KeyPackageRef;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct KeyPackageKv<S: KvExt + Send + Sync>(pub S);

// TODO: change when ': ToString' constraint on persistence crate lifted
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[repr(transparent)]
pub struct MlsKeyPackageEntityId(String);

impl MlsKeyPackageEntityId {
    const B64: base64::engine::GeneralPurpose = base64::prelude::BASE64_URL_SAFE_NO_PAD;
}

impl std::fmt::Display for MlsKeyPackageEntityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&[u8]> for MlsKeyPackageEntityId {
    fn from(id: &[u8]) -> Self {
        id.to_vec().into()
    }
}

impl From<Vec<u8>> for MlsKeyPackageEntityId {
    fn from(id: Vec<u8>) -> Self {
        WickrKeyPackageRef::from(id).into()
    }
}

impl From<WickrKeyPackageRef> for MlsKeyPackageEntityId {
    fn from(kp_ref: WickrKeyPackageRef) -> Self {
        use base64::Engine as _;
        Self(Self::B64.encode(&*kp_ref))
    }
}

impl From<KeyPackageRef> for MlsKeyPackageEntityId {
    fn from(kp_ref: KeyPackageRef) -> Self {
        WickrKeyPackageRef::from(kp_ref).into()
    }
}

impl TryFrom<&MlsKeyPackageEntityId> for WickrKeyPackageRef {
    type Error = MlsError;

    fn try_from(id: &MlsKeyPackageEntityId) -> Result<Self, Self::Error> {
        Ok(MlsKeyPackageEntityId::B64.decode(id.0.as_bytes())?.into())
    }
}

impl TryFrom<&MlsKeyPackageEntityId> for KeyPackageRef {
    type Error = MlsError;

    fn try_from(id: &MlsKeyPackageEntityId) -> Result<Self, Self::Error> {
        Ok(WickrKeyPackageRef::try_from(id)?.into())
    }
}

/// A KeyPackage data model
/// /!\ DO NOT CHANGE THE SERIALIZATION NAMES OF THE FIELDS UNLESS YOU ALSO HAVE A DATABASE MIGRATION IN PLACE
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MlsKeyPackageEntity {
    /// Unique identifier
    /// serde rename allows for persistence crate to treat this as the primary key since it relies
    /// on reflection. Has to be the same as [MlsEntity::ID_COLUMN].
    #[serde(rename = "id")]
    id: MlsKeyPackageEntityId,
    #[serde(rename = "value")]
    pub value: WickrKeyPackage,
}

impl crate::Entity for MlsKeyPackageEntity {
    type Id = MlsKeyPackageEntityId;
    const TABLE_NAME: &str = "mls_key_package";
    const ID_COLUMN: &str = "id";

    fn id(&self) -> &Self::Id {
        &self.id
    }
}

impl MlsEntity for MlsKeyPackageEntity {}

#[async_trait::async_trait]
impl<S: KvExt + Send + Sync> mls_rs_core::key_package::KeyPackageStorage for KeyPackageKv<S> {
    type Error = WickrProviderError;

    async fn get(&self, id: &[u8]) -> Result<Option<WickrKeyPackage>, Self::Error> {
        let id = id.into();
        tracing::debug!("Fetching KeyPackage '{id}'");
        Ok(self.0.maybe_get::<MlsKeyPackageEntity>(&id).await?.map(|e| e.value))
    }

    async fn insert(&mut self, id: Vec<u8>, value: WickrKeyPackage) -> Result<(), Self::Error> {
        let id = id.into();
        tracing::debug!("Storing KeyPackage '{id}'");
        let value = MlsKeyPackageEntity { id, value };
        Ok(self.0.set::<MlsKeyPackageEntity>(&value).await?)
    }

    async fn delete(&mut self, id: &[u8]) -> Result<(), Self::Error> {
        let id = id.into();
        tracing::debug!("Deleting KeyPackage '{id}'");
        Ok(self.remove::<MlsKeyPackageEntity>(&id).await?)
    }

    async fn insert_all(&mut self, kps: &HashMap<Vec<u8>, WickrKeyPackage>) -> Result<(), Self::Error> {
        let kps = kps
            .iter()
            .map(|(id, value)| MlsKeyPackageEntity {
                id: id.as_slice().into(),
                value: value.clone(),
            })
            .collect::<Vec<_>>();
        Ok(self.0.set_all(kps).await?)
    }
}

impl MlsKeyPackageEntity {
    pub fn kp_ref(&self) -> MlsResult<KeyPackageRef> {
        (&self.id).try_into()
    }
}

impl TryFrom<MlsKeyPackageEntity> for mls_types::KeyPackage {
    type Error = MlsError;

    fn try_from(entity: MlsKeyPackageEntity) -> Result<Self, Self::Error> {
        entity.try_into()
    }
}
