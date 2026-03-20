use crate::types::leaf_node::LeafNodeSource;
use crate::{CipherSuite, Credential, CredentialType, MlsTypesError, MlsTypesResult, types::leaf_node::LeafNode};
use hex::ToHex;
use std::pin::pin;

// TODO: own this type
#[derive(
    Debug,
    Clone,
    PartialEq,
    serde::Serialize,
    serde::Deserialize,
    mls_rs_codec::MlsSize,
    mls_rs_codec::MlsEncode,
    mls_rs_codec::MlsDecode,
)]
pub struct KeyPackage(pub Box<mls_rs::KeyPackage>);

impl Eq for KeyPackage {}

impl std::ops::Deref for KeyPackage {
    type Target = mls_rs::KeyPackage;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl KeyPackage {
    #[allow(clippy::unwrap_used)]
    pub fn kp_ref(&self) -> MlsTypesResult<KeyPackageRef> {
        use mls_rs::CryptoProvider as _;
        let cs = self.cipher_suite;
        let crypto_provider = mls_rs_crypto_rustcrypto::RustCryptoProvider::with_enabled_cipher_suites(vec![cs]);
        // SAFETY: Should be infallible in our case
        let cp = crypto_provider.cipher_suite_provider(cs).unwrap();

        let kp_ref = pin!(self.0.as_ref().to_reference(&cp));
        let kp_ref = kp_ref.poll(&mut std::task::Context::from_waker(&futures::task::noop_waker()));
        let core::task::Poll::Ready(kp_ref) = kp_ref else {
            return Err(MlsTypesError::ImplementationError("Async hashing API in mls-rs !!!"));
        };
        Ok(KeyPackageRef(kp_ref?))
    }

    pub fn credential(&self) -> MlsTypesResult<Credential> {
        self.signing_identity().credential.clone().try_into()
    }

    pub fn credential_type(&self) -> MlsTypesResult<CredentialType> {
        self.signing_identity().credential.credential_type().try_into()
    }

    pub fn ciphersuite(&self) -> MlsTypesResult<CipherSuite> {
        self.cipher_suite.try_into()
    }

    pub fn leaf_node(&self) -> MlsTypesResult<LeafNode> {
        self.leaf_node.clone().try_into()
    }

    pub fn expiry(&self) -> MlsTypesResult<core::time::Duration> {
        let LeafNodeSource::KeyPackage(lifetime) = self.leaf_node()?.leaf_node_source else {
            return Err(MlsTypesError::ImplementationError(
                "A KeyPackage does not have a LeafNode with KeyPackage source !",
            ));
        };
        Ok(core::time::Duration::from_secs(lifetime.not_after))
    }
}

// TODO: own this type
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    mls_rs_codec::MlsSize,
    mls_rs_codec::MlsEncode,
    mls_rs_codec::MlsDecode,
)]
pub struct KeyPackageRef(mls_rs::KeyPackageRef);

impl KeyPackageRef {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<mls_rs::KeyPackageRef> for KeyPackageRef {
    fn from(value: mls_rs::KeyPackageRef) -> Self {
        Self(value)
    }
}

impl From<KeyPackageRef> for mls_rs::KeyPackageRef {
    fn from(value: KeyPackageRef) -> Self {
        value.to_vec().into()
    }
}

impl From<Vec<u8>> for KeyPackageRef {
    fn from(v: Vec<u8>) -> Self {
        Self(v.into())
    }
}

impl From<KeyPackageRef> for Vec<u8> {
    fn from(v: KeyPackageRef) -> Self {
        v.as_ref().to_vec()
    }
}

impl AsRef<[u8]> for KeyPackageRef {
    fn as_ref(&self) -> &[u8] {
        std::ops::Deref::deref(&self.0)
    }
}

impl std::ops::Deref for KeyPackageRef {
    type Target = mls_rs::KeyPackageRef;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Display for KeyPackageRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_ref().encode_hex::<String>())
    }
}
