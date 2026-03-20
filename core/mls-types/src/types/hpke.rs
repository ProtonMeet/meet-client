use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};

#[derive(MlsSize, MlsEncode, MlsDecode)]
pub struct HpkeKeyPair {
    pub hpke_public_key: HpkePublicKey,
    pub hpke_secret_key: HpkeSecretKey,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, MlsSize, MlsDecode, MlsEncode)]
pub struct HpkePublicKey(pub(crate) Vec<u8>);

impl std::ops::Deref for HpkePublicKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(MlsSize, MlsEncode, MlsDecode, zeroize::ZeroizeOnDrop)]
pub struct HpkeSecretKey(pub(crate) Vec<u8>);
