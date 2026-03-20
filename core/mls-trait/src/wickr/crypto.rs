use crate::{MlsError, traits::crypto::MlsCryptoTrait};
use mls_rs::{
    SignContent,
    crypto::{SignaturePublicKey, SignatureSecretKey},
};
use mls_rs_codec::MlsEncode as _;
use mls_rs_core::crypto::{CipherSuiteProvider as _, CryptoProvider as _};
use mls_types::CipherSuite;

pub struct MlsCrypto;

impl MlsCryptoTrait for MlsCrypto {
    async fn try_sign_with_label(
        ciphersuite: CipherSuite,
        secret_key: &[u8],
        content: &[u8],
        label: &str,
    ) -> crate::MlsResult<mls_types::Signature> {
        let provider = mls_rs_crypto_rustcrypto::RustCryptoProvider::new();
        let cs_provider = provider
            .cipher_suite_provider(ciphersuite.into())
            .ok_or(MlsError::ImplementationError(
                "A client had not ciphersuite provider initialized",
            ))?;

        let sign_content = SignContent::new_with_raw_label(label, content.to_vec());
        let tbs = sign_content.mls_encode_to_vec()?;
        let signature_key = SignatureSecretKey::new_slice(secret_key);
        let signature = cs_provider.sign(&signature_key, &tbs).await?;

        Ok(signature.into())
    }

    async fn verify_with_label(
        ciphersuite: CipherSuite,
        public_key: &[u8],
        content: &[u8],
        label: &str,
        signature: &[u8],
    ) -> crate::MlsResult<()> {
        let provider = mls_rs_crypto_rustcrypto::RustCryptoProvider::new();
        let cs_provider = provider
            .cipher_suite_provider(ciphersuite.into())
            .ok_or(MlsError::ImplementationError(
                "A client had not ciphersuite provider initialized",
            ))?;

        let sign_content = SignContent::new_with_raw_label(label, content.to_vec());
        let tbs = sign_content.mls_encode_to_vec()?;

        let pk = SignaturePublicKey::new_slice(public_key);

        cs_provider.verify(&pk, signature, &tbs).await?;
        Ok(())
    }
}
