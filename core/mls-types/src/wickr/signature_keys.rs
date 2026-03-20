use crate::types::signature::SignaturePublicKey;
use mls_rs::crypto::SignaturePublicKey as WickrSignaturePublicKey;

impl From<WickrSignaturePublicKey> for SignaturePublicKey {
    fn from(v: WickrSignaturePublicKey) -> Self {
        Self(v)
    }
}
impl From<SignaturePublicKey> for WickrSignaturePublicKey {
    fn from(v: SignaturePublicKey) -> Self {
        v.0
    }
}
