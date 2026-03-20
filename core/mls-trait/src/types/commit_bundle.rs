use mls_types::{MlsMessage, PublicRatchetTree};

#[derive(Debug)]
#[cfg_attr(feature = "test-utils", derive(Clone))]
pub struct CommitBundle {
    pub commit: MlsMessage,
    pub welcome: Option<MlsMessage>,
    pub group_info: Option<MlsMessage>,
    pub ratchet_tree: Option<PublicRatchetTree>,
    pub contains_update_path: bool,
}

impl CommitBundle {
    pub fn has_update_path(&self) -> bool {
        self.contains_update_path
    }
}
