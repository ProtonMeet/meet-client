use mls_rs::group::Member;
use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};

#[derive(Debug, Clone, MlsDecode, MlsEncode, MlsSize)]
pub struct PublicRatchetTree(pub Box<mls_rs::group::ExportedTree<'static>>);

impl From<mls_rs::group::ExportedTree<'static>> for PublicRatchetTree {
    fn from(tree: mls_rs::group::ExportedTree<'static>) -> Self {
        Self(Box::new(tree))
    }
}

impl From<PublicRatchetTree> for mls_rs::group::ExportedTree<'static> {
    fn from(tree: PublicRatchetTree) -> Self {
        *tree.0
    }
}

impl PublicRatchetTree {
    pub fn members(&self) -> impl Iterator<Item = Member> {
        self.0.as_ref().members_iter()
    }
}
