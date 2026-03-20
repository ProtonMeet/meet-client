use mls_types::{CipherSuite, Signature};

use crate::MlsResult;

#[allow(async_fn_in_trait)]
pub trait MlsCryptoTrait {
    async fn try_sign_with_label(
        ciphersuite: CipherSuite,
        secret_key: &[u8],
        message: &[u8],
        label: &str,
    ) -> MlsResult<Signature>;

    async fn verify_with_label(
        ciphersuite: CipherSuite,
        public_key: &[u8],
        message: &[u8],
        label: &str,
        signature: &[u8],
    ) -> MlsResult<()>;
}
