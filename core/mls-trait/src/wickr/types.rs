use crate::{MlsError, types::CommitBundle};

impl TryFrom<mls_rs::group::CommitOutput> for CommitBundle {
    type Error = MlsError;

    fn try_from(v: mls_rs::group::CommitOutput) -> Result<Self, Self::Error> {
        let mls_rs::group::CommitOutput {
            commit_message,
            mut welcome_messages,
            ratchet_tree,
            external_commit_group_info,
            contains_update_path,
            ..
        } = v;
        let welcome = match welcome_messages.len() {
            0 => None,
            1 => Some(welcome_messages.remove(0)),
            _ => {
                return Err(MlsError::ImplementationError(
                    "mls-rs should have been configured to return a single Welcome",
                ));
            }
        }
        .map(Into::into);

        let ratchet_tree = ratchet_tree.map(Into::into);
        let group_info = external_commit_group_info.map(Into::into);

        Ok(Self {
            commit: commit_message.into(),
            welcome,
            ratchet_tree,
            group_info,
            contains_update_path,
        })
    }
}
