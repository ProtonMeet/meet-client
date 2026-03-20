use crate::tls_codec::Deserialize;
use crate::{
    Capabilities, MlsTypesError,
    wickr::{ciphersuite, credential_type, extension, proposal, protocol_version},
};
use mls_rs::group::Capabilities as WickrCapabilities;
use mls_rs_codec::MlsEncode;

impl From<Capabilities> for WickrCapabilities {
    fn from(Capabilities(value): Capabilities) -> Self {
        Self {
            protocol_versions: value
                .versions
                .into_iter()
                .map(protocol_version::mls_spec_to_mls_rs)
                .collect(),
            cipher_suites: value
                .ciphersuites
                .into_iter()
                .map(ciphersuite::mls_spec_to_mls_rs)
                .collect(),
            extensions: value
                .extensions
                .into_iter()
                .map(extension::mls_spec_to_mls_rs)
                .collect(),
            proposals: value.proposals.into_iter().map(proposal::mls_spec_to_mls_rs).collect(),
            credentials: value
                .credentials
                .into_iter()
                .map(credential_type::mls_spec_to_mls_rs)
                .collect(),
        }
    }
}

impl TryFrom<WickrCapabilities> for Capabilities {
    type Error = MlsTypesError;

    fn try_from(value: WickrCapabilities) -> Result<Self, Self::Error> {
        Ok(Self::tls_deserialize(&mut value.mls_encode_to_vec()?.as_slice())?)
    }
}
