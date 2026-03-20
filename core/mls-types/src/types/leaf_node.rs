use crate::{
    Capabilities, Extensions, MlsTypesResult, mls_spec,
    types::support::{Lifetime, ParentHash},
};
use meet_mls::reexports::mimi_protocol_mls::reexports::tls_codec::Deserialize as _;
use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, MlsSize, MlsEncode, MlsDecode)]
pub struct LeafNode {
    pub public_key: mls_rs::crypto::HpkePublicKey,
    pub signing_identity: mls_rs::identity::SigningIdentity,
    pub capabilities: mls_rs::group::Capabilities,
    pub leaf_node_source: LeafNodeSource,
    pub extensions: mls_rs::ExtensionList,
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    #[serde(with = "crate::vec_serde")]
    pub signature: Vec<u8>,
}

impl LeafNode {
    pub fn application_data(&self) -> MlsTypesResult<Option<mls_rs::group::ApplicationDataDictionary>> {
        let extensions = &self.extensions.0;
        Ok(extensions
            .iter()
            .find_map(|extension| {
                if extension.extension_type == mls_spec::drafts::mls_extensions::EXTENSION_APP_DATA_DICT.into() {
                    let data = &mut extension.extension_data.as_slice();
                    Some(mls_rs::group::ApplicationDataDictionary::mls_decode(data))
                } else {
                    None
                }
            })
            .transpose()?)
    }

    pub fn application_data_spec(
        &self,
    ) -> MlsTypesResult<Option<mls_spec::drafts::mls_extensions::safe_application::ApplicationDataDictionary>> {
        let extensions = &self.extensions.0;
        Ok(extensions
            .iter()
            .find_map(|extension| {
                if extension.extension_type == mls_spec::drafts::mls_extensions::EXTENSION_APP_DATA_DICT.into() {
                    let data = &mut extension.extension_data.as_slice();
                    Some(
                        mls_spec::drafts::mls_extensions::safe_application::ApplicationDataDictionary::tls_deserialize(
                            data,
                        ),
                    )
                } else {
                    None
                }
            })
            .transpose()?)
    }

    pub fn extensions(&self) -> MlsTypesResult<Extensions> {
        self.extensions.clone().try_into()
    }

    pub fn capabilities(&self) -> MlsTypesResult<Capabilities> {
        self.capabilities.clone().try_into()
    }

    pub fn capabilities_spec(&self) -> MlsTypesResult<mls_spec::defs::Capabilities> {
        Ok(mls_spec::defs::Capabilities::tls_deserialize(
            &mut self.capabilities.mls_encode_to_vec()?.as_slice(),
        )?)
    }
}

const LNS_KP: u8 = mls_spec::tree::leaf_node::LeafNodeSourceType::KeyPackage as u8;
const LNS_UPDATE: u8 = mls_spec::tree::leaf_node::LeafNodeSourceType::Update as u8;
const LNS_COMMIT: u8 = mls_spec::tree::leaf_node::LeafNodeSourceType::Commit as u8;

#[derive(PartialEq, Eq, Debug, Clone, MlsSize, MlsEncode, MlsDecode, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum LeafNodeSource {
    KeyPackage(Lifetime) = LNS_KP,
    Update = LNS_UPDATE,
    Commit(ParentHash) = LNS_COMMIT,
}
