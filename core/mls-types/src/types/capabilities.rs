use crate::{mls_spec, tls_codec};

#[derive(Debug, Clone, PartialEq, Eq, tls_codec::TlsSize, tls_codec::TlsSerialize, tls_codec::TlsDeserialize)]
pub struct Capabilities(pub(crate) mls_spec::defs::Capabilities);

impl std::ops::Deref for Capabilities {
    type Target = mls_spec::defs::Capabilities;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for Capabilities {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<mls_spec::defs::Capabilities> for Capabilities {
    fn from(value: mls_spec::defs::Capabilities) -> Self {
        Self(value)
    }
}
