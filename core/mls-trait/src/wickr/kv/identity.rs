use crate::{
    KvError, KvExt,
    kv::{MlsEntity, SignaturePK},
};
use mls_rs::crypto::SignatureSecretKey;
use mls_types::CipherSuite;
use time::OffsetDateTime;

#[derive(Debug, Clone)]
/// Identity is responsible for storing the identity of a client (identity being the secret/public key pair)
pub struct IdentityKv<S: KvExt + Send + Sync>(pub S);

/// A cryptographic identity data model
/// /!\ DO NOT CHANGE THE SERIALIZATION NAMES OF THE FIELDS UNLESS YOU ALSO HAVE A DATABASE MIGRATION IN PLACE
#[derive(serde::Serialize, serde::Deserialize)]
#[must_use]
pub struct MlsIdentityEntity {
    /// Unique identifier. Signature public key
    /// serde rename allows for persistence crate to treat this as the primary key since it relies
    /// on reflection. Has to be the same as [MlsEntity::ID_COLUMN].
    #[serde(rename = "id")]
    pub(crate) signature_pk: SignaturePK,
    #[serde(rename = "ciphersuite")]
    pub(crate) cs: CipherSuite,
    #[serde(rename = "secret")]
    /// Client signature secret key
    pub(crate) signature_sk: SignatureSecretKey,
    #[serde(default = "default_time", with = "time::serde::timestamp::milliseconds")]
    created_at: OffsetDateTime,
}

impl MlsIdentityEntity {
    pub fn new(signature_pk: SignaturePK, cs: CipherSuite, signature_sk: SignatureSecretKey) -> Self {
        Self {
            signature_pk,
            cs,
            signature_sk,
            created_at: OffsetDateTime::now_utc(),
        }
    }
}

fn default_time() -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH
}

impl std::fmt::Debug for MlsIdentityEntity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlsIdentityEntity")
            .field("signature_pk", &self.signature_pk)
            .field("signature_sk", &"***")
            .field("ciphersuite", &self.cs)
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl crate::Entity for MlsIdentityEntity {
    type Id = SignaturePK;
    const TABLE_NAME: &str = "mls_identity";
    const ID_COLUMN: &str = "id";

    fn id(&self) -> &Self::Id {
        &self.signature_pk
    }
}

impl MlsEntity for MlsIdentityEntity {}

impl<S: KvExt + Send + Sync> IdentityKv<S> {
    pub async fn insert(&self, identity: &MlsIdentityEntity) -> Result<(), KvError> {
        tracing::debug!("Saving identity {identity:?}");
        match self.0.insert(identity).await? {
            crate::InsertOutput::Inserted => Ok(()),
            crate::InsertOutput::AlreadyExists => {
                tracing::warn!("Tried to insert duplicate MlsIdentityEntity");
                Ok(())
            }
        }
    }

    pub async fn restore(&self, signature_pk: SignaturePK) -> Result<Option<MlsIdentityEntity>, KvError> {
        tracing::debug!("Restoring identity");
        Ok(match self.0.maybe_get(&signature_pk).await {
            Ok(entity) => entity,
            Err(KvError::NotFound(_)) => None,
            Err(error) => return Err(error),
        })
    }
}
