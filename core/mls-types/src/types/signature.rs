use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, MlsSize, MlsEncode, MlsDecode)]
#[repr(transparent)]
#[serde(transparent)]
pub struct SignaturePublicKey(pub(crate) mls_rs::crypto::SignaturePublicKey);

impl std::ops::Deref for SignaturePublicKey {
    type Target = mls_rs::crypto::SignaturePublicKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, MlsSize, MlsEncode, MlsDecode)]
#[repr(transparent)]
#[serde(transparent)]
pub struct Signature(#[serde(with = "serde_bytes")] pub(crate) Vec<u8>);

impl From<Vec<u8>> for Signature {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl From<Signature> for Vec<u8> {
    fn from(value: Signature) -> Self {
        value.0
    }
}

impl From<SignaturePublicKey> for Vec<u8> {
    fn from(v: SignaturePublicKey) -> Self {
        v.0.into()
    }
}

impl std::ops::Deref for Signature {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
