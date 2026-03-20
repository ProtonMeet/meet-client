use crate::{Credential, SignaturePublicKey};

#[derive(Clone, PartialEq)]
pub struct SigningIdentity {
    pub signature_key: SignaturePublicKey,
    pub credential: Credential,
}
