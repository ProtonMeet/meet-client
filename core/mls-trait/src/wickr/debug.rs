use base64::Engine;
use mls_rs::{ExtensionList, group::Capabilities};
use mls_rs_codec::MlsEncode;

use crate::{Initialized, KvExt, MlsGroup, MlsGroupTrait};

impl<Kv: KvExt + Send + Sync + Clone> std::fmt::Debug for MlsGroup<Kv, Initialized> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tree = self.ratchet_tree().members_iter().map(Member::from).collect::<Vec<_>>();
        f.debug_struct("MlsGroup")
            .field("ratchet tree", &tree)
            .field("pending commit", &self.0.pending_commit())
            .field("pending proposals", &self.0.pending_proposals().collect::<Vec<_>>())
            .field("context extensions", self.0.context().extensions())
            .finish()
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct Member {
    /// The index of this member within a group.
    ///
    /// This value is consistent for all clients and will not change as the
    /// group evolves.
    index: u32,
    signature_public_key: String,
    credential: String,
    /// Current identity public key and credential of this member.
    /// Current client [Capabilities] of this member.
    capabilities: Capabilities,
    /// Current leaf node extensions in use by this member.
    extensions: ExtensionList,
}

impl From<mls_rs_core::group::Member> for Member {
    fn from(member: mls_rs_core::group::Member) -> Self {
        let signature_public_key = hex::encode(member.signing_identity.signature_key.as_bytes());
        let credential = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(
            member
                .signing_identity
                .credential
                .mls_encode_to_vec()
                .expect("credential should encode correctly"),
        );

        Self {
            index: member.index,
            signature_public_key,
            credential,
            capabilities: member.capabilities,
            extensions: member.extensions,
        }
    }
}
