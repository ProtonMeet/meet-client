use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};

#[derive(Clone, Debug, MlsDecode, MlsEncode, MlsSize)]
pub struct Psk(pub(crate) mls_rs::psk::PreSharedKey);

#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct ExternalPskId(#[serde(with = "serde_bytes")] pub Vec<u8>);

#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    zeroize::ZeroizeOnDrop,
)]
#[repr(transparent)]
#[serde(transparent)]
pub struct ExternalPsk(#[serde(with = "serde_bytes")] pub Vec<u8>);

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PskReference {
    External(ExternalPskId),
}
