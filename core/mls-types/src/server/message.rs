use crate::mls_spec;
use crate::{KeyPackage, MlsMessage, MlsTypesError, tls_codec};
use mls_rs_codec::{MlsDecode, MlsEncode};
use mls_spec::reexports::tls_codec::Serialize;
use tls_codec::Deserialize;

impl TryFrom<MlsMessage> for crate::mls_spec::messages::PublicMessage {
    type Error = MlsTypesError;

    fn try_from(m: MlsMessage) -> Result<Self, Self::Error> {
        let m = m
            .mls_message
            .into_plaintext()
            .ok_or(MlsTypesError::ImplementationError("Not a PublicMessage"))?;
        let m = m.mls_encode_to_vec()?;
        Ok(Self::tls_deserialize(&mut m.as_slice())?)
    }
}

impl TryFrom<MlsMessage> for mls_spec::messages::PrivateMessage {
    type Error = MlsTypesError;

    fn try_from(m: MlsMessage) -> Result<Self, Self::Error> {
        let m = m
            .mls_message
            .into_ciphertext()
            .ok_or(MlsTypesError::ImplementationError("Not a PrivateMessage"))?;
        let m = m.mls_encode_to_vec()?;
        Ok(Self::tls_deserialize(&mut m.as_slice())?)
    }
}

impl TryFrom<MlsMessage> for mls_spec::group::welcome::Welcome {
    type Error = MlsTypesError;

    fn try_from(m: MlsMessage) -> Result<Self, Self::Error> {
        let w = m
            .mls_message
            .into_welcome()
            .ok_or(MlsTypesError::ImplementationError("Not a Welcome"))?;
        let w = w.mls_encode_to_vec()?;
        Ok(Self::tls_deserialize(&mut w.as_slice())?)
    }
}

impl TryFrom<MlsMessage> for crate::mimi_protocol_mls::room_state::GroupInfoOption {
    type Error = MlsTypesError;

    fn try_from(m: MlsMessage) -> Result<Self, Self::Error> {
        let gi = m
            .mls_message
            .into_group_info()
            .ok_or(MlsTypesError::ImplementationError("Not a GroupInfo"))?;
        let gi = gi.mls_encode_to_vec()?;
        Ok(Self::Full {
            group_info: mls_spec::group::group_info::GroupInfo::tls_deserialize(&mut gi.as_slice())?,
        })
    }
}

impl TryFrom<KeyPackage> for mls_spec::key_package::KeyPackage {
    type Error = MlsTypesError;

    fn try_from(value: KeyPackage) -> Result<Self, Self::Error> {
        let tls = value.mls_encode_to_vec()?;
        Ok(Self::tls_deserialize(&mut tls.as_slice())?)
    }
}

impl TryFrom<mls_spec::key_package::KeyPackage> for KeyPackage {
    type Error = MlsTypesError;

    fn try_from(value: mls_spec::key_package::KeyPackage) -> Result<Self, Self::Error> {
        let tls = value.tls_serialize_detached()?;
        Ok(Self::mls_decode(&mut tls.as_slice())?)
    }
}
