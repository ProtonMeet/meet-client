use crate::mls_spec::{Parsable, drafts::mls_extensions::content_advertisement::ApplicationFraming};
use crate::{CommitOutput, KvExt, MlsError, MlsGroup, MlsResult};
use meet_identifiers::LeafIndex;
use mls_rs::{
    self,
    group::{ApplicationDataDictionary, CommitEffect, CommitMessageDescription, proposal::ReInitProposal},
    mls_rules::ProposalInfo,
};
use mls_types::{LeafNode, MediaType, Member, MlsTypesError};

#[derive(Debug)]
pub enum ReceivedMessage {
    ApplicationMessage {
        sender: LeafIndex,
        media_type: MediaType,
        content: Vec<u8>,
    },
    Commit {
        output: CommitOutput,
        contained_proposals_by_ref: bool,
    },
    ReInit {
        reinit: ProposalInfo<ReInitProposal>,
        commit: CommitMessageDescription,
        old_roster: Vec<Member>,
        contained_proposals_by_ref: bool,
    },
    Proposal,
    /// Message was issued by ourselves and fanned out to us. We can ignore it.
    SelfMessage,
    /// Used by paginated decryption to bubble up the error to the consumer
    Error(MlsTypesError),
    /// This message was ignored because a previous commit decryption failed hence decryption of this message CANNOT succeed
    /// Once you receive we have to find a way to rejoin the group and rejoining via external commit IS NOT an option
    /// because nobody wants to rejoin a staled group
    Ignored,
    /// The sender sent something from a wrong MLS state. This does not indicate whether it is a bug
    /// or a deliberate attempt to derail the group.
    /// Nevertheless, it should be ignored
    Corrupted,
    /// We already decrypted this message recently
    Duplicate,
    /// The message could not be decrypted because the local epoch does not match the epoch of the message
    EpochMismatch,
}

#[derive(Debug)]
pub struct ReceivedMessages(Vec<ReceivedMessage>);

impl From<Vec<ReceivedMessage>> for ReceivedMessages {
    fn from(v: Vec<ReceivedMessage>) -> Self {
        Self(v)
    }
}

impl std::ops::Deref for ReceivedMessages {
    type Target = [ReceivedMessage];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl IntoIterator for ReceivedMessages {
    type Item = ReceivedMessage;

    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl ReceivedMessages {
    pub fn expect_contains_exactly_app_messages(&self, messages: &[&'static str]) {
        assert_eq!(
            self.0.len(),
            messages.len(),
            "Expected {} messages, found {}",
            messages.len(),
            self.0.len()
        );
        for m in &self.0 {
            let ReceivedMessage::ApplicationMessage { content: m, .. } = m else {
                panic!("Method misuse")
            };
            #[allow(clippy::unwrap_used)]
            let m = std::str::from_utf8(m.as_ref()).unwrap();
            assert!(messages.contains(&m), "Expected messages to contain {m} but it did not")
        }
    }
}

pub enum ReceivedNewMemberMessage {
    Welcome { sender: LeafIndex },
}

impl ReceivedNewMemberMessage {
    pub fn get_sender(&self) -> LeafIndex {
        match self {
            Self::Welcome { sender, .. } => *sender,
        }
    }
}

pub struct PreviousGroupState {
    pub roster: Vec<Member>,
    pub app_data: Option<ApplicationDataDictionary>,
}

impl ReceivedMessage {
    pub fn compute<Kv: KvExt + Send + Sync + Clone>(
        group: &MlsGroup<Kv>,
        v: mls_rs::group::ReceivedMessage,
        mut old_state: PreviousGroupState,
        commit_contained_proposals_by_ref: bool,
        new_leaf_node: Option<LeafNode>,
    ) -> MlsResult<Self> {
        Ok(match v {
            mls_rs::group::ReceivedMessage::ApplicationMessage(m) => {
                let app_framing = ApplicationFraming::from_tls_bytes(m.data())?;

                Self::ApplicationMessage {
                    sender: m.sender_index.try_into()?,
                    media_type: MediaType::try_from(app_framing.media_type)?,
                    content: app_framing.inner_application_content,
                }
            }
            mls_rs::group::ReceivedMessage::Commit(commit)
                if matches!(&commit.effect, CommitEffect::NewEpoch(_))
                    || matches!(&commit.effect, CommitEffect::Removed { .. }) =>
            {
                if let CommitEffect::NewEpoch(ref new_epoch) | CommitEffect::Removed { ref new_epoch, .. } =
                    commit.effect
                {
                    tracing::debug!(
                        committer = commit.committer,
                        epoch.prev = new_epoch.prior_state.context.epoch,
                        epoch.new = new_epoch.epoch,
                        "Commit"
                    );
                }
                let output = CommitOutput::compute(group, &mut old_state, commit, new_leaf_node)?;
                Self::Commit {
                    output,
                    contained_proposals_by_ref: commit_contained_proposals_by_ref,
                }
            }
            mls_rs::group::ReceivedMessage::Commit(commit) if matches!(&commit.effect, CommitEffect::ReInit(_)) => {
                // SAFETY: we check beforehand that the effect is of the right type
                let CommitEffect::ReInit(reinit) = &commit.effect else {
                    unreachable!()
                };
                // TODO: what to do with this ? https://www.rfc-editor.org/rfc/rfc9420.html#section-12.2-3.9
                Self::ReInit {
                    reinit: reinit.clone(),
                    commit,
                    old_roster: old_state.roster,
                    contained_proposals_by_ref: commit_contained_proposals_by_ref,
                }
            }
            mls_rs::group::ReceivedMessage::Proposal(_) => Self::Proposal,
            _ => return Err(MlsError::ImplementationError("Unexpected received message type")),
        })
    }
}

impl TryFrom<mls_rs::group::NewMemberInfo> for ReceivedNewMemberMessage {
    type Error = MlsError;

    fn try_from(nmi: mls_rs::group::NewMemberInfo) -> Result<Self, Self::Error> {
        Ok(Self::Welcome {
            sender: nmi.sender.try_into()?,
        })
    }
}
