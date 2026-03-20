use crate::MlsTypesError;
use mls_rs_codec::{MlsDecode, MlsEncode};

impl TryFrom<crate::LeafNode> for mls_rs::LeafNode {
    type Error = MlsTypesError;

    fn try_from(value: crate::LeafNode) -> Result<Self, Self::Error> {
        Ok(Self::mls_decode(&mut value.mls_encode_to_vec()?.as_slice())?)
    }
}

impl TryFrom<mls_rs::LeafNode> for crate::LeafNode {
    type Error = MlsTypesError;

    fn try_from(value: mls_rs::LeafNode) -> Result<Self, Self::Error> {
        Ok(Self::mls_decode(&mut value.mls_encode_to_vec()?.as_slice())?)
    }
}
