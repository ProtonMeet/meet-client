use crate::{KvExt, kv::MlsEntity, wickr::error::WickrProviderError};
use mls_rs_core::psk::{ExternalPskId as WickrPskId, PreSharedKey as WickrPsk};

#[derive(Debug, Clone)]
pub struct PskKv<S: KvExt + Send + Sync>(pub S);

// TODO: change when ': ToString' constraint on persistence crate lifted
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[repr(transparent)]
pub struct PskEntityId(String);

impl std::fmt::Display for PskEntityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&[u8]> for PskEntityId {
    fn from(id: &[u8]) -> Self {
        id.to_vec().into()
    }
}

impl From<Vec<u8>> for PskEntityId {
    fn from(id: Vec<u8>) -> Self {
        WickrPskId::from(id).into()
    }
}

impl From<WickrPskId> for PskEntityId {
    fn from(id: WickrPskId) -> Self {
        use base64::Engine as _;
        Self(base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(&*id))
    }
}

/// A PreSharedKey data model
/// /!\ DO NOT CHANGE THE SERIALIZATION NAMES OF THE FIELDS UNLESS YOU ALSO HAVE A DATABASE MIGRATION IN PLACE
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MlsPskEntity {
    /// Unique identifier
    /// serde rename allows for persistence crate to treat this as the primary key since it relies
    /// on reflection. Has to be the same as [MlsEntity::ID_COLUMN].
    #[serde(rename = "id")]
    id: PskEntityId,
    #[serde(rename = "value")]
    value: WickrPsk,
}

impl MlsPskEntity {
    pub fn new(id: WickrPskId, value: WickrPsk) -> Self {
        Self {
            id: id.into(),
            value,
        }
    }
}

impl crate::Entity for MlsPskEntity {
    type Id = PskEntityId;
    const TABLE_NAME: &str = "mls_psk";
    const ID_COLUMN: &str = "id";

    fn id(&self) -> &Self::Id {
        &self.id
    }
}

impl MlsEntity for MlsPskEntity {}

impl<S: KvExt + Send + Sync> PskKv<S> {
    pub async fn insert_external_psk(
        &self,
        id: WickrPskId,
        value: WickrPsk,
    ) -> Result<(), WickrProviderError> {
        let value = MlsPskEntity::new(id, value);
        Ok(self.0.set::<MlsPskEntity>(&value).await?)
    }

    pub async fn remove_external_psk(&self, id: &WickrPskId) -> Result<(), WickrProviderError> {
        let id = id.clone().into();
        Ok(self.0.remove::<MlsPskEntity>(&id).await?)
    }

    pub async fn contains_external_psk(&self, id: &WickrPskId) -> Result<bool, WickrProviderError> {
        let id = id.clone().into();
        Ok(self.0.maybe_get::<MlsPskEntity>(&id).await?.is_some())
    }
}

#[async_trait::async_trait]
impl<S: KvExt + Send + Sync> mls_rs_core::psk::PreSharedKeyStorage for PskKv<S> {
    type Error = WickrProviderError;

    async fn get(&self, id: &WickrPskId) -> Result<Option<WickrPsk>, Self::Error> {
        let id = id.clone().into();
        tracing::debug!("Fetching PSK '{id}'");
        Ok(self.0.maybe_get::<MlsPskEntity>(&id).await?.map(|e| e.value))
    }
}
