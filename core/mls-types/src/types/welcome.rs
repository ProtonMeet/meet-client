use crate::{CipherSuite, KeyPackageRef, MlsTypesResult};
use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};

#[derive(Clone, Debug, MlsDecode, MlsEncode, MlsSize)]
pub struct Welcome(pub(crate) mls_rs::group::Welcome);

#[derive(Debug)]
pub struct WelcomeRef<'w>(pub(crate) &'w mls_rs::group::Welcome);

impl Welcome {
    pub fn ciphersuite(&self) -> MlsTypesResult<CipherSuite> {
        self.0.cipher_suite.try_into()
    }

    pub fn kp_refs(&self) -> Vec<KeyPackageRef> {
        self.0.secrets.iter().map(|s| s.new_member.clone().into()).collect()
    }
}

impl WelcomeRef<'_> {
    pub fn ciphersuite(&self) -> MlsTypesResult<CipherSuite> {
        self.0.cipher_suite.try_into()
    }

    pub fn kp_refs(&self) -> Vec<KeyPackageRef> {
        self.0.secrets.iter().map(|s| s.new_member.clone().into()).collect()
    }
}
