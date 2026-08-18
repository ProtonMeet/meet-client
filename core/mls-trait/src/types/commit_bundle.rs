use mls_types::{MlsMessage, PublicRatchetTree};

use crate::MlsError;

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

    pub fn from_reinit_welcome_messages<C: mls_rs::client_config::ClientConfig + Clone>(
        group: &mls_rs::Group<C>,
        mut welcome_messages: Vec<mls_rs::MlsMessage>,
    ) -> Result<Self, MlsError> {
        let welcome = match welcome_messages.len() {
            0 => None,
            1 => Some(welcome_messages.remove(0).into()),
            _ => {
                return Err(MlsError::ImplementationError(
                    "mls-rs should have been configured to return a single Welcome",
                ));
            }
        };

        let ratchet_tree = Some(group.export_tree().into_owned().into());
        let commit = welcome
            .clone()
            .ok_or(MlsError::ImplementationError("ReInit commit produced no welcome"))?;

        Ok(Self {
            commit,
            welcome,
            ratchet_tree,
            group_info: None,
            contains_update_path: true,
        })
    }
}
