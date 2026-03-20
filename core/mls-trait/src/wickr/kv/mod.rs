mod group;
mod identity;
mod kp;
mod psk;

use crate::kv::SignaturePK;
pub use group::{GroupKv, MlsGroupEntity};
pub use identity::{IdentityKv, MlsIdentityEntity};
pub use kp::{KeyPackageKv, MlsKeyPackageEntity, MlsKeyPackageEntityId};
pub use psk::{MlsPskEntity, PskKv};

macro_rules! impl_kvext {
    ($struct_name:ident) => {
        impl<S: crate::KvExt + Send + Sync> crate::KvExt for $struct_name<S> {
            #[inline(always)]
            fn maybe_get<V: crate::MlsEntity>(
                &self,
                key: &<V as crate::Entity>::Id,
            ) -> impl std::future::Future<Output = Result<Option<V>, crate::KvError>> + Send {
                self.0.maybe_get(key)
            }

            #[inline(always)]
            fn insert<V: crate::MlsEntity>(
                &self,
                value: &V,
            ) -> impl std::future::Future<Output = Result<crate::InsertOutput, crate::KvError>> + Send {
                self.0.insert(value)
            }

            #[inline(always)]
            fn set<V: crate::MlsEntity>(
                &self,
                value: &V,
            ) -> impl std::future::Future<Output = Result<(), crate::KvError>> + Send {
                self.0.set(value)
            }

            #[inline(always)]
            fn set_all<V: crate::MlsEntity>(
                &self,
                values: Vec<V>,
            ) -> impl std::future::Future<Output = Result<(), crate::KvError>> + Send {
                self.0.set_all(values)
            }

            #[inline(always)]
            fn remove<V: crate::MlsEntity>(
                &self,
                key: &<V as crate::Entity>::Id,
            ) -> impl std::future::Future<Output = Result<(), crate::KvError>> + Send {
                self.0.remove::<V>(key)
            }

            #[inline(always)]
            fn remove_all<V: crate::MlsEntity>(
                &self,
                keys: impl ExactSizeIterator<Item = <V as crate::Entity>::Id> + Send,
            ) -> impl std::future::Future<Output = Result<(), crate::KvError>> + Send {
                self.0.remove_all::<V>(keys)
            }

            #[inline(always)]
            fn get_all<V: crate::MlsEntity>(
                &self,
            ) -> impl std::future::Future<Output = Result<Vec<V>, crate::KvError>> + Send {
                self.0.get_all::<V>()
            }

            #[inline(always)]
            fn count<V: crate::MlsEntity>(
                &self,
            ) -> impl std::future::Future<Output = Result<u32, crate::KvError>> + Send {
                self.0.count::<V>()
            }
        }
    };
}

impl_kvext!(GroupKv);
impl_kvext!(KeyPackageKv);
impl_kvext!(PskKv);
impl_kvext!(IdentityKv);

impl From<mls_rs::crypto::SignaturePublicKey> for SignaturePK {
    fn from(value: mls_rs::crypto::SignaturePublicKey) -> Self {
        Self(value.as_bytes().to_owned())
    }
}

impl From<&mls_rs::crypto::SignaturePublicKey> for SignaturePK {
    fn from(value: &mls_rs::crypto::SignaturePublicKey) -> Self {
        Self(value.as_bytes().to_owned())
    }
}

impl From<SignaturePK> for mls_rs::crypto::SignaturePublicKey {
    fn from(value: SignaturePK) -> Self {
        Self::new(value.0)
    }
}
