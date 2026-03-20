use crate::{KvExt, kv::MlsEntity, wickr::error::WickrProviderError};
use meet_identifiers::GroupId;
use mls_rs_core::group::{EpochRecord as WickrEpochRecord, GroupState as WickrGroupState};
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct GroupKv<S: KvExt + Send + Sync>(pub S);

/// A MLS Group data model
/// /!\ DO NOT CHANGE THE SERIALIZATION NAMES OF THE FIELDS UNLESS YOU ALSO HAVE A DATABASE MIGRATION IN PLACE
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MlsGroupEntity {
    /// Unique identifier
    /// serde rename allows for persistence crate to treat this as the primary key since it relies
    /// on reflection. Has to be the same as [MlsEntity::ID_COLUMN].
    #[serde(rename = "id")]
    pub id: GroupId,
    #[serde(rename = "state")]
    pub state: GroupStateRecord,
    #[serde(rename = "epoch_records")]
    epoch_records: BTreeMap<u64, EpochRecord>,
}

impl MlsGroupEntity {
    fn try_new(
        state: WickrGroupState,
        epoch_records: impl IntoIterator<Item = EpochRecord>,
    ) -> Result<Self, WickrProviderError> {
        Ok(Self {
            id: state.id.as_slice().try_into()?,
            state: state.into(),
            epoch_records: epoch_records.into_iter().map(|e| (e.id, e)).collect(),
        })
    }

    pub fn take_epoch(mut self, epoch: u64) -> Option<EpochRecord> {
        self.epoch_records.remove(&epoch)
    }

    pub fn get_mut_epoch(&mut self, epoch: u64) -> Option<&mut EpochRecord> {
        self.epoch_records.get_mut(&epoch)
    }

    pub fn insert_epoch(&mut self, epoch: EpochRecord) {
        let Some(old) = self.epoch_records.insert(epoch.id, epoch) else {
            return;
        };
        tracing::error!(epoch.id = old.id, "Inserted duplicate epoch");
    }

    // This function does not fail if an update can't be made. If the epoch
    // is not in the store, then it can no longer be accessed by future
    // get_epoch calls and is no longer relevant.
    pub fn update_epoch(&mut self, epoch: EpochRecord) {
        if let Some(existing_epoch) = self.get_mut_epoch(epoch.id) {
            *existing_epoch = epoch
        }
    }

    pub fn trim_epochs(&mut self, max_epoch_retention: usize) {
        while self.epoch_records.len() > max_epoch_retention {
            if let Some((id, _)) = self.epoch_records.pop_first() {
                tracing::debug!(epoch = id, "Trimmed epoch");
            }
        }
    }

    pub fn storage_size(&self) -> usize {
        self.state
            .data
            .len()
            .saturating_add(self.epoch_records.values().map(|e| e.data.len()).sum())
    }
}

impl crate::Entity for MlsGroupEntity {
    type Id = GroupId;
    const TABLE_NAME: &str = "mls_group";
    const ID_COLUMN: &str = "id";

    fn id(&self) -> &Self::Id {
        &self.id
    }
}

impl MlsEntity for MlsGroupEntity {}

#[cfg_attr(any(test, feature = "test-utils"), derive(Clone))]
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GroupStateRecord {
    #[serde(with = "serde_bytes")]
    pub id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

impl From<WickrGroupState> for GroupStateRecord {
    fn from(value: WickrGroupState) -> Self {
        Self {
            id: value.id,
            data: value.data,
        }
    }
}

impl From<GroupStateRecord> for WickrGroupState {
    fn from(value: GroupStateRecord) -> Self {
        Self {
            id: value.id,
            data: value.data,
        }
    }
}

#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EpochRecord {
    pub id: u64,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

impl From<WickrEpochRecord> for EpochRecord {
    fn from(v: WickrEpochRecord) -> Self {
        Self { id: v.id, data: v.data }
    }
}

#[async_trait::async_trait]
impl<S: KvExt + Send + Sync> mls_rs_core::group::GroupStateStorage for GroupKv<S> {
    type Error = WickrProviderError;

    async fn max_epoch_id(&self, id: &[u8]) -> Result<Option<u64>, Self::Error> {
        let id = id.try_into()?;
        tracing::debug!("Fetching max epoch id for group '{id}'");
        let Some(mut group) = self.0.maybe_get::<MlsGroupEntity>(&id).await? else {
            return Ok(None);
        };
        // Even though it looks like it's removing an epoch it's not as `group`
        // is not written back to the database.
        // Calling `pop_last` avoids a call to `clone`
        let epoch = group.epoch_records.pop_last().map(|e| e.0);
        Ok(epoch)
    }

    async fn state(&self, id: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        let id = id.try_into()?;
        tracing::debug!("Fetching state for group '{id}'");
        let group = self.0.get::<MlsGroupEntity>(&id).await?;
        let state = group.state.data;
        Ok(Some(state))
    }

    async fn epoch(&self, id: &[u8], epoch: u64) -> Result<Option<Vec<u8>>, Self::Error> {
        let id = id.try_into()?;
        tracing::debug!("Fetching epoch {epoch} for group '{id}'");
        let group = self.0.get::<MlsGroupEntity>(&id).await?;
        // Even though it looks like it's removing an epoch it's not as `group`
        // is not written back to the database.
        // `take_epoch` consumes `group` and avoids a call to `clone`
        let record = group.take_epoch(epoch);
        let epoch_data = record.map(|r| r.data);
        Ok(epoch_data)
    }

    async fn write(
        &mut self,
        state: WickrGroupState,
        new_records: Vec<WickrEpochRecord>,
        updated_records: Vec<WickrEpochRecord>,
    ) -> Result<(), Self::Error> {
        let id = state.id.as_slice().try_into()?;
        tracing::debug!("Storing group '{id}'");

        let old_group = self.0.maybe_get::<MlsGroupEntity>(&id).await?;
        let mut entity = match old_group {
            Some(mut entity) => {
                entity.state = state.into();
                entity
            }
            None => MlsGroupEntity::try_new(state, [])?,
        };
        for new in new_records {
            entity.insert_epoch(new.into())
        }
        for record in updated_records {
            entity.update_epoch(record.into())
        }

        entity.trim_epochs(crate::MAX_EPOCH_RETENTION);
        Ok(self.0.set(&entity).await?)
    }
}

