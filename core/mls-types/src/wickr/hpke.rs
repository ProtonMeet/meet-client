use crate::types::hpke::{HpkePublicKey, HpkeSecretKey};

impl From<HpkePublicKey> for mls_rs::crypto::HpkePublicKey {
    fn from(k: HpkePublicKey) -> Self {
        k.0.into()
    }
}

impl From<mls_rs::crypto::HpkePublicKey> for HpkePublicKey {
    fn from(k: mls_rs::crypto::HpkePublicKey) -> Self {
        Self(Vec::<u8>::from(k))
    }
}

impl From<HpkeSecretKey> for mls_rs::crypto::HpkeSecretKey {
    fn from(mut k: HpkeSecretKey) -> Self {
        Self::from(std::mem::take(&mut k.0))
    }
}

impl From<mls_rs::crypto::HpkeSecretKey> for HpkeSecretKey {
    fn from(k: mls_rs::crypto::HpkeSecretKey) -> Self {
        Self(k.as_ref().to_vec())
    }
}
