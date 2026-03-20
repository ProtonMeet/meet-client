use crate::{MlsTypesError, PublicRatchetTree, mls_spec, tls_codec};
use mls_rs_codec::MlsDecode;
use tls_codec::{Deserialize, Serialize};

impl TryFrom<PublicRatchetTree> for mls_spec::drafts::ratchet_tree_options::RatchetTreeOption {
    type Error = MlsTypesError;

    fn try_from(ratchet_tree: PublicRatchetTree) -> Result<Self, Self::Error> {
        let ratchet_tree = ratchet_tree.0.to_bytes()?;
        let ratchet_tree = mls_spec::tree::RatchetTree::tls_deserialize(&mut ratchet_tree.as_slice())?;
        let ratchet_tree = Self::Full { ratchet_tree };
        Ok(ratchet_tree)
    }
}

impl TryFrom<mls_spec::drafts::ratchet_tree_options::RatchetTreeOption> for PublicRatchetTree {
    type Error = MlsTypesError;

    fn try_from(ratchet_tree: mls_spec::drafts::ratchet_tree_options::RatchetTreeOption) -> Result<Self, Self::Error> {
        let ratchet_tree = match ratchet_tree {
            mls_spec::drafts::ratchet_tree_options::RatchetTreeOption::Full { ratchet_tree } => {
                ratchet_tree.tls_serialize_detached()?
            }
            _ => unreachable!(),
        };
        let ratchet_tree = Self::mls_decode(&mut ratchet_tree.as_slice())?;
        Ok(ratchet_tree)
    }
}
