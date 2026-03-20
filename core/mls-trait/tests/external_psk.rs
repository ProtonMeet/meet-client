use mls_rs_core::psk::{ExternalPskId as WickrPskId, PreSharedKey as WickrPsk, PreSharedKeyStorage};
use mls_trait::{Entity, InsertOutput, KvError, KvExt, MlsEntity, ProposalArg, ProposalEffect};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct InMemoryKv {
    tables: Arc<Mutex<HashMap<&'static str, HashMap<String, serde_json::Value>>>>,
}

impl InMemoryKv {
    fn lock_tables(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, HashMap<&'static str, HashMap<String, serde_json::Value>>>, KvError> {
        self.tables.lock().map_err(|_| KvError::InternalError)
    }
}

impl KvExt for InMemoryKv {
    async fn maybe_get<V: MlsEntity>(&self, key: &<V as Entity>::Id) -> Result<Option<V>, KvError> {
        let tables = self.lock_tables()?;
        let Some(table) = tables.get(V::table_name()) else {
            return Ok(None);
        };
        let Some(raw) = table.get(&key.to_string()) else {
            return Ok(None);
        };
        serde_json::from_value(raw.clone())
            .map(Some)
            .map_err(|e| KvError::DeserializationError(e.to_string()))
    }

    async fn insert<V: MlsEntity>(&self, value: &V) -> Result<InsertOutput, KvError> {
        let mut tables = self.lock_tables()?;
        let table = tables.entry(V::table_name()).or_default();
        let key = value.id().to_string();
        if table.contains_key(&key) {
            return Ok(InsertOutput::AlreadyExists);
        }

        let raw =
            serde_json::to_value(value).map_err(|e| KvError::SerializationError(e.to_string()))?;
        table.insert(key, raw);
        Ok(InsertOutput::Inserted)
    }

    async fn set<V: MlsEntity>(&self, value: &V) -> Result<(), KvError> {
        let mut tables = self.lock_tables()?;
        let table = tables.entry(V::table_name()).or_default();
        let key = value.id().to_string();
        let raw =
            serde_json::to_value(value).map_err(|e| KvError::SerializationError(e.to_string()))?;
        table.insert(key, raw);
        Ok(())
    }

    async fn set_all<V: MlsEntity>(&self, values: Vec<V>) -> Result<(), KvError> {
        for value in values {
            self.set(&value).await?;
        }
        Ok(())
    }

    async fn remove<V: MlsEntity>(&self, key: &<V as Entity>::Id) -> Result<(), KvError> {
        let mut tables = self.lock_tables()?;
        if let Some(table) = tables.get_mut(V::table_name()) {
            table.remove(&key.to_string());
        }
        Ok(())
    }

    async fn remove_all<V: MlsEntity>(
        &self,
        keys: impl ExactSizeIterator<Item = <V as Entity>::Id> + Send,
    ) -> Result<(), KvError> {
        for key in keys {
            self.remove::<V>(&key).await?;
        }
        Ok(())
    }

    async fn get_all<V: MlsEntity>(&self) -> Result<Vec<V>, KvError> {
        let tables = self.lock_tables()?;
        let Some(table) = tables.get(V::table_name()) else {
            return Ok(vec![]);
        };
        table
            .values()
            .cloned()
            .map(|raw| serde_json::from_value(raw).map_err(|e| KvError::DeserializationError(e.to_string())))
            .collect()
    }

    async fn count<V: MlsEntity>(&self) -> Result<u32, KvError> {
        let tables = self.lock_tables()?;
        let count = tables.get(V::table_name()).map(|table| table.len()).unwrap_or_default();
        Ok(count as u32)
    }
}

#[tokio::test]
async fn external_psk_store_roundtrip() {
    let kv = InMemoryKv::default();
    let store = mls_trait::wickr::kv::PskKv(kv);

    let id = WickrPskId::from(vec![0x01, 0x02, 0x03]);
    let psk = WickrPsk::from(vec![0xAA, 0xBB, 0xCC]);

    assert!(!store.contains_external_psk(&id).await.unwrap());

    store.insert_external_psk(id.clone(), psk.clone()).await.unwrap();
    assert!(store.contains_external_psk(&id).await.unwrap());
    assert_eq!(PreSharedKeyStorage::get(&store, &id).await.unwrap(), Some(psk.clone()));

    store.remove_external_psk(&id).await.unwrap();
    assert!(!store.contains_external_psk(&id).await.unwrap());
    assert_eq!(PreSharedKeyStorage::get(&store, &id).await.unwrap(), None);
}

#[test]
fn proposal_arg_psk_external_variant_is_available() {
    let id = mls_types::ExternalPskId(vec![0x10, 0x20]);
    let arg = ProposalArg::PskExternal { id: id.clone() };
    match arg {
        ProposalArg::PskExternal { id: actual } => assert_eq!(actual, id),
        _ => panic!("expected ProposalArg::PskExternal"),
    }
}

#[test]
fn psk_added_discriminant_is_stable() {
    let effect = ProposalEffect::PskAdded {
        reference: mls_types::PskReference::External(mls_types::ExternalPskId(vec![0x42])),
    };
    assert_eq!(effect.discriminant(), 0x0C);
}
