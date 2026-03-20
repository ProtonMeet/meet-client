pub mod error;
mod server;
mod types;
pub mod wickr;

pub(crate) use meet_mls::reexports::mimi_protocol_mls::{
    self,
    reexports::{mls_spec, tls_codec},
};

use mls_rs_codec::MlsDecode as _;
use mls_spec::drafts::mls_extensions::safe_application::Component;

pub use {
    error::{MlsTypesError, MlsTypesResult},
    types::{
        Secret,
        capabilities::Capabilities,
        ciphersuite::{CipherSuite, HashAlgorithm, SignatureAlgorithm},
        content_type::ContentType,
        credential::{Credential, CredentialClaims, CredentialExt},
        credential_type::CredentialType,
        extensions::{AppDataDictionaryExt, ExtensionListExt, Extensions},
        group_info::{GroupInfo, GroupInfoExt, GroupInfoRef},
        hpke::{HpkeKeyPair, HpkePublicKey, HpkeSecretKey},
        key_package::{KeyPackage, KeyPackageRef},
        leaf_node::LeafNode,
        media_type::{MediaType, MediaTypeList, MediaTypeParameter},
        member::Member,
        mls_message::MlsMessage,
        proposal::Proposal,
        protocol_version::ProtocolVersion,
        psk::{ExternalPsk, ExternalPskId, PskReference},
        ratchet_tree::PublicRatchetTree,
        sender::Sender,
        signature::{Signature, SignaturePublicKey},
        signing_identity::SigningIdentity,
        welcome::{Welcome, WelcomeRef},
        wire_format::WireFormat,
    },
};

pub(crate) mod vec_serde {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            hex::serde::serialize(v, s)
        } else {
            serde_bytes::serialize(v, s)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        if d.is_human_readable() {
            hex::serde::deserialize(d)
        } else {
            serde_bytes::deserialize(d)
        }
    }
}

pub fn get_component<C: Component + tls_codec::Deserialize>(
    application_data: &mls_rs::group::ApplicationDataDictionary,
) -> mls_spec::MlsSpecResult<Option<C>> {
    application_data.component_data
        .iter()
        .find_map(|component| {
            if component.component_id == C::component_id() {
                Some(C::from_tls_bytes(component.data.as_slice()))
            } else {
                None
            }
        })
        // the list is supposed to be sorted, with unique components
        .transpose()
}

pub fn set_component<C: Component + tls_codec::Serialize>(
    application_data: &mut mls_rs::group::ApplicationDataDictionary,
    component: &C,
) -> mls_spec::MlsSpecResult<()> {
    let found = application_data
        .component_data
        .iter_mut()
        .find(|component| component.component_id == C::component_id())
        .map(|c| {
            c.data = component.tls_serialize_detached()?;
            mls_spec::MlsSpecResult::Ok(())
        })
        .transpose()?;
    if found.is_none() {
        // FIXME: urgently use mls-spec everywhere
        let new_component = mls_rs::group::ComponentData::mls_decode(
            &mut component.tls_serialize_detached()?.as_slice(),
        )
        .map_err(|_| {
            mls_spec::MlsSpecError::TlsCodecError(tls_codec::Error::DecodingError(
                "Invalid AppComponent format".to_string(),
            ))
        })?;
        application_data.component_data.push(new_component);
    }
    Ok(())
}

pub fn get_spec_component<C: Component + tls_codec::Deserialize>(
    application_data: &mls_spec::drafts::mls_extensions::safe_application::ApplicationDataDictionary,
) -> mls_spec::MlsSpecResult<Option<C>> {
    application_data.component_data
        .iter()
        .find_map(|(component_id, data)| {
            if *component_id == C::component_id() {
                Some(C::from_tls_bytes(data.as_slice()))
            } else {
                None
            }
        })
        // the list is supposed to be sorted, with unique components
        .transpose()
}
