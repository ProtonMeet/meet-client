use base64::Engine;
use mls_types::SignaturePublicKey;
use serde::de::DeserializeOwned;
use std::{
    fmt::{Debug, Display},
    future::Future,
};

/// Marker trait for Persistent Data models
pub trait Entity: serde::Serialize + serde::de::DeserializeOwned + Send + Sync {
    type Id: ToString + Clone + Send + Sync;
    const TABLE_NAME: &str;
    const ID_COLUMN: &str;

    fn table_name() -> &'static str {
        Self::TABLE_NAME
    }

    fn id_column() -> &'static str {
        Self::ID_COLUMN
    }

    fn id(&self) -> &Self::Id;
}

/// Result of an insert operation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertOutput {
    Inserted,
    AlreadyExists,
}

pub trait MlsEntity: Entity {}

pub trait KvExt {
    fn get<V: MlsEntity>(&self, key: &<V as Entity>::Id) -> impl Future<Output = Result<V, KvError>> + Send {
        use futures_util::future::FutureExt as _;
        self.maybe_get(key)
            .map(move |r| r.and_then(|v: Option<V>| v.map_or_else(|| Err(KvError::InternalError), |v| Ok(v))))
    }

    fn maybe_get<V: MlsEntity>(
        &self,
        key: &<V as Entity>::Id,
    ) -> impl Future<Output = Result<Option<V>, KvError>> + Send;

    fn get_field<'a, V, F>(
        &'a self,
        key: &<V as Entity>::Id,
        extractor: fn(V) -> F,
    ) -> impl Future<Output = Result<F, KvError>> + Send
    where
        V: MlsEntity + 'a,
        F: DeserializeOwned + Send + 'a,
    {
        use futures_util::future::FutureExt as _;
        self.get(key).map(move |r| r.map(|v: V| extractor(v)))
    }

    fn insert<V: MlsEntity>(&self, value: &V) -> impl Future<Output = Result<InsertOutput, KvError>> + Send;

    fn set<V: MlsEntity>(&self, value: &V) -> impl Future<Output = Result<(), KvError>> + Send;

    fn set_all<V: MlsEntity>(&self, values: Vec<V>) -> impl Future<Output = Result<(), KvError>> + Send;

    fn remove<V: MlsEntity>(&self, key: &<V as Entity>::Id) -> impl Future<Output = Result<(), KvError>> + Send;

    fn remove_all<V: MlsEntity>(
        &self,
        keys: impl ExactSizeIterator<Item = <V as Entity>::Id> + Send,
    ) -> impl Future<Output = Result<(), KvError>> + Send;

    fn get_all<V: MlsEntity>(&self) -> impl Future<Output = Result<Vec<V>, KvError>> + Send;

    fn count<V: MlsEntity>(&self) -> impl Future<Output = Result<u32, KvError>> + Send;
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum KvError {
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
    #[error("Could not find key {0:?} in database")]
    NotFound(String),
    #[error("Key {0:?} already exists")]
    AlreadyExists(String),
    #[error("Error from the provider: {0}")]
    ProviderError(String),
    #[error("Unknown table or store {0}")]
    TableNotFound(&'static str),
    #[error("Internal error")]
    InternalError,
}

/// Mls Client signature public key wrapper
#[derive(PartialEq, Eq, Hash, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignaturePK(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl Display for SignaturePK {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", base64::prelude::BASE64_STANDARD_NO_PAD.encode(&self.0))
    }
}

impl Debug for SignaturePK {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", base64::prelude::BASE64_STANDARD_NO_PAD.encode(&self.0))
    }
}

impl From<Vec<u8>> for SignaturePK {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<SignaturePublicKey> for SignaturePK {
    #[inline]
    fn from(value: SignaturePublicKey) -> Self {
        Vec::<u8>::from(value).into()
    }
}
