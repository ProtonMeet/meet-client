use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};

#[derive(Clone, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode, serde::Serialize, serde::Deserialize)]
pub struct Lifetime {
    pub not_before: u64,
    pub not_after: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode, serde::Serialize, serde::Deserialize)]
pub struct ParentHash(
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    #[serde(with = "crate::vec_serde")]
    Vec<u8>,
);
