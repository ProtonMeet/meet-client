use crate::types::psk::{ExternalPsk, ExternalPskId, Psk};

impl From<mls_rs::psk::PreSharedKey> for Psk {
    fn from(psk: mls_rs::psk::PreSharedKey) -> Self {
        Self(psk)
    }
}
impl From<Psk> for mls_rs::psk::PreSharedKey {
    fn from(psk: Psk) -> Self {
        psk.0
    }
}

impl From<ExternalPskId> for mls_rs::psk::ExternalPskId {
    fn from(id: ExternalPskId) -> Self {
        Self::from(id.0)
    }
}

impl From<mls_rs::psk::ExternalPskId> for ExternalPskId {
    fn from(id: mls_rs::psk::ExternalPskId) -> Self {
        Self(id.as_ref().to_vec())
    }
}

impl From<ExternalPsk> for mls_rs::psk::PreSharedKey {
    fn from(mut psk: ExternalPsk) -> Self {
        Self::from(std::mem::take(&mut psk.0))
    }
}

impl From<mls_rs::psk::PreSharedKey> for ExternalPsk {
    fn from(psk: mls_rs::psk::PreSharedKey) -> Self {
        Self(psk.as_ref().to_vec())
    }
}
