use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};

pub mod capabilities;
pub mod ciphersuite;
pub mod content_type;
pub mod credential;
pub mod credential_type;
pub mod extensions;
pub mod group_info;
pub mod hpke;
pub mod key_package;
pub mod leaf_node;
pub mod media_type;
pub mod member;
pub mod mls_message;
pub mod proposal;
pub mod protocol_version;
pub mod psk;
pub mod ratchet_tree;
pub mod sender;
pub mod signature;
pub mod signing_identity;
pub mod support;
pub mod text_message;
pub mod welcome;
pub mod wire_format;

#[derive(MlsSize, MlsEncode, MlsDecode, zeroize::ZeroizeOnDrop)]
pub struct Secret(pub(crate) Vec<u8>);

impl From<Vec<u8>> for Secret {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl std::ops::Deref for Secret {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
