use crate::{KeyPackage, MlsMessage, MlsTypesError};
use mls_rs::framing::MlsMessagePayload;

impl From<mls_rs::KeyPackage> for KeyPackage {
    fn from(value: mls_rs::KeyPackage) -> Self {
        Self(Box::new(value))
    }
}

impl From<KeyPackage> for mls_rs::MlsMessage {
    fn from(value: KeyPackage) -> Self {
        Self {
            version: value.version,
            payload: MlsMessagePayload::KeyPackage(*value.0),
        }
    }
}

impl From<KeyPackage> for MlsMessage {
    fn from(value: KeyPackage) -> Self {
        Self {
            mls_message: Box::new(value.into()),
            virtual_time: None,
        }
    }
}

impl TryFrom<MlsMessage> for KeyPackage {
    type Error = MlsTypesError;

    fn try_from(value: MlsMessage) -> Result<Self, Self::Error> {
        value
            .into_key_package()
            .ok_or(MlsTypesError::InvalidMlsMessage("Expected KeyPackage"))
    }
}
