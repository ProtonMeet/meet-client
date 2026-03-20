use crate::meet_policy::UserRole;
use crate::mimi_protocol_mls::{
    ParticipantListData, ParticipantListUpdate, UserRolePair,
    components::metadata::RoomMetadata,
    reexports::mls_spec::{self, Parsable, drafts::mls_extensions::safe_application::Component, group::ExternalSender},
};
use crate::{
    KvExt, MlsError, MlsGroup, MlsGroupTrait, MlsResult,
    types::{
        AppliedProposal, ClaimsetDiff, CommitOutput, ParticipantListEffect, PreviousGroupState, ProposalEffect,
        UserIdRolePair,
    },
};
use ahash::{HashMap, HashMapExt};
use identity::{ProtonMeetIdentity as _, SdKbt};
use meet_identifiers::{ByRef, DeviceId, Epoch, LeafIndex, ProtonMeetIdError, UserId};
use mls_rs::group::{CommitEffect, CommitMessageDescription, ComponentId};
use mls_types::{Credential, LeafNode, Member, MlsMessage, Proposal, get_component};
use proton_claims::reexports::CwtAny as _;

impl CommitOutput {
    /// Computes the output of an applied `commit`
    ///
    /// # Arguments
    ///
    /// * `group` - Borrow of the committed group. Used to extract some data of the new epoch
    /// * `old_roster` - Roster of the previous epoch. Used to find removed member identities and
    ///   proposal senders
    /// * `commit` - Commit description, containing the new epoch applied proposals
    #[tracing::instrument(skip_all, err)]
    pub fn compute<S: KvExt + Send + Sync + Clone>(
        group: &MlsGroup<S>,
        old_state: &mut PreviousGroupState,
        commit: CommitMessageDescription,
        updated_leaf_node: Option<LeafNode>,
    ) -> MlsResult<Self> {
        let mut committer = group.find_member(commit.committer.try_into()?)?.into_credential();
        let committer_device_id = committer.device_id()?;
        let new_epoch = match commit.effect {
            CommitEffect::NewEpoch(new_epoch) | CommitEffect::Removed { new_epoch, .. } => new_epoch,
            CommitEffect::ReInit(reinit) => {
                let old_cs = group.ciphersuite()?;
                let new_cs = reinit.proposal.new_cipher_suite().try_into()?;
                let new_ciphersuite = (old_cs != new_cs).then_some(new_cs);
                let new_group_id = reinit.proposal.group_id().try_into()?;

                let old_protocol_version = group.0.protocol_version();
                let reinit_version = reinit.proposal.new_version();
                let new_protocol_version = (old_protocol_version != reinit_version)
                    .then_some(reinit_version)
                    .map(TryInto::try_into)
                    .transpose()?;

                let sender = reinit.sender.try_into()?;
                let mut sender = group.find_sender(&sender)?.ok_or(MlsError::ImplementationError(
                    "ReInit proposals not on a member or external sender",
                ))?;

                let proposal = AppliedProposal {
                    sender: sender.device_id()?,
                    effect: ProposalEffect::ReInit {
                        new_ciphersuite,
                        new_group_id,
                        new_protocol_version,
                    },
                };
                return Ok(Self {
                    applied_proposals: vec![proposal],
                    unused_proposals: vec![],
                    committer: committer_device_id,
                    epoch: 0.into(),
                });
            }
        };
        // This cannot fail, even if the self node was removed
        let own_leaf_index = group.own_leaf_index()?;
        let epoch = new_epoch.epoch.into();
        let mut applied_proposals = Vec::with_capacity(new_epoch.applied_proposals.len());

        let old_app_data = old_state.app_data.as_ref();
        let old_participant_list = old_app_data
            .and_then(|d| get_component::<ParticipantListData>(d).ok())
            .flatten();

        // slightly more performant but ultimately requires batching finding the members
        let mut device_id_cache = HashMap::<u32, DeviceId>::new();

        for proposal in new_epoch.applied_proposals {
            use mls_rs::group::Sender as WickrSender;
            let sender = match proposal.sender {
                WickrSender::Member(leaf_index) => {
                    match proposal.proposal {
                        mls_rs::group::proposal::Proposal::Update(ref p) => {
                            // an Update proposal is always sent by the owner of the LeafNode so we can read the DeviceId directly from the proposal
                            let mut credential: Credential = p.signing_identity().credential.clone().try_into()?;
                            credential.device_id()?
                        }
                        _ => match device_id_cache.get(&leaf_index) {
                            Some(sender_device_id) => sender_device_id.clone(),
                            None => {
                                let sender_device_id = find_device(&old_state.roster, leaf_index.try_into()?)?;
                                device_id_cache.insert(leaf_index, sender_device_id.clone());
                                sender_device_id
                            }
                        },
                    }
                }
                WickrSender::NewMemberCommit => committer_device_id.clone(),
                WickrSender::External(idx) => {
                    let external_senders = group.external_senders()?.unwrap_or_default();
                    let ext_sender: &ExternalSender = external_senders
                        .get(idx as usize)
                        .ok_or(MlsError::ExternalSenderNotFound(idx))?;
                    match &ext_sender.credential {
                        mls_spec::credential::Credential::SdCwtCredential(
                            mls_spec::drafts::sd_cwt_credential::SdCwtCredential { sd_kbt },
                        ) => SdKbt::from_cbor_bytes(&sd_kbt[..])?.device_id()?,
                        _ => {
                            let ct = mls_spec::defs::CredentialType::from(&ext_sender.credential);
                            return Err(MlsError::UnsupportedExternalSenderCredential(*ct));
                        }
                    }
                }
                WickrSender::NewMemberProposal => match &proposal.proposal {
                    mls_rs::group::proposal::Proposal::Add(add) => {
                        let mut cred: Credential =
                            add.key_package().signing_identity().credential.clone().try_into()?;
                        cred.device_id()?
                    }
                    _ => {
                        return Err(MlsError::ImplementationError(
                            "Invalid proposal kind for `NewMemberProposal` sender",
                        ));
                    }
                },
                _ => unreachable!(),
            };
            let context = ProposalContext {
                old_roster: &mut old_state.roster,
                own_user: None,
                own_leaf: Some(own_leaf_index),
                old_participant_list: old_participant_list.as_ref(),
            };
            let effect = ProposalEffect::compute_commit(proposal.proposal.try_into()?, &mut committer, context)?;
            applied_proposals.push(AppliedProposal { sender, effect });
        }

        // in order not to clutter the API, we masquerade the UpdatePath as an Update proposal
        if let Some(ln) = updated_leaf_node.filter(|_| !commit.is_external) {
            let mut new_credential: Credential = ln.signing_identity.credential.try_into()?;
            let claimset_diff = ProposalEffect::compute_credential_diff(&mut new_credential, &mut old_state.roster)?;
            let effect = ProposalEffect::Update {
                claimset_diff,
                new_credential,
            };
            let as_update_proposal = AppliedProposal {
                sender: committer_device_id.clone(),
                effect,
            };
            applied_proposals.push(as_update_proposal);
        }

        let unused_proposals = new_epoch
            .unused_proposals
            .into_iter()
            .map(|p| p.proposal.try_into())
            .collect::<Result<_, _>>()?;
        Ok(Self {
            applied_proposals,
            unused_proposals,
            committer: committer_device_id,
            epoch,
        })
    }

    /// Computes the output of an applied `external commit`
    ///
    /// # Arguments
    ///
    /// * `message` - a MLS message containing the external commit
    pub fn compute_ext_commit(
        message: &MlsMessage,
        epoch: Epoch,
        old_roster: &mut [Member],
        own_user: &UserId,
    ) -> MlsResult<Self> {
        let mut credentials = message
            .sender_credential()?
            .map(Ok)
            .unwrap_or_else(|| Err(MlsError::ImplementationError("No credential in external commit")))?;
        let device_id = credentials.device_id()?;

        if let Some(proposals) = message.proposals_by_value() {
            let proposals = proposals
                .map(|p| {
                    ProposalEffect::compute_external_commit(p, &mut credentials, old_roster, own_user).map(|effect| {
                        AppliedProposal {
                            sender: device_id.clone(),
                            effect,
                        }
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;

            Ok(Self {
                applied_proposals: proposals,
                unused_proposals: vec![],
                committer: device_id,
                epoch,
            })
        } else {
            Err(MlsError::ImplementationError(
                "External commit message does not contains proposals",
            ))
        }
    }
}

fn find_device(old_roster: &[Member], index: LeafIndex) -> MlsResult<DeviceId> {
    old_roster
        .iter()
        .find(|m| m.leaf_index() == index)
        .ok_or(MlsError::MemberNotFound(index))?
        .credential()
        .to_owned()
        .device_id()
        .map_err(Into::into)
}

struct ProposalContext<'a> {
    old_roster: &'a mut [Member],
    own_user: Option<&'a UserId>,
    own_leaf: Option<LeafIndex>,
    old_participant_list: Option<&'a ParticipantListData>,
}

impl ProposalEffect {
    /// Will compute an effect from an external commit.
    /// It differs from the `compute_commit` method in that an external commit does not have the full context of the group when applied (only the previous roster)
    /// # Arguments
    ///
    /// * `value` - the proposal to transform into a ProposalEffect
    /// * `committer` - the commiter of the proposal
    fn compute_external_commit(
        proposal: Proposal,
        committer: &mut Credential,
        old_roster: &mut [Member],
        own_user: &UserId,
    ) -> MlsResult<Self> {
        // External commit effect do not have context since it means the device was not part of the group before the commit was applied
        Self::compute(
            proposal,
            committer,
            ProposalContext {
                old_roster,
                own_user: Some(own_user),
                own_leaf: None,
                old_participant_list: None,
            },
        )
    }

    /// Will compute an effect from a commit.
    /// It defers from the `compute_commit` method in that an external commit does not have the context of the group when applied
    /// # Arguments
    ///
    /// * `value` - the proposal to transform into a ProposalEffect
    /// * `committer` - the commiter of the proposal
    /// * `context` - the roster of the group, the leaf of the current user and the participant list at the moment the proposal was created
    ///
    fn compute_commit(value: Proposal, committer: &mut Credential, context: ProposalContext<'_>) -> MlsResult<Self> {
        Self::compute(value, committer, context)
    }

    fn compute(value: Proposal, committer: &mut Credential, context: ProposalContext) -> MlsResult<Self> {
        let v = match value {
            Proposal::Add(add_proposal) => {
                let cred = add_proposal
                    .key_package()
                    .signing_identity()
                    .credential
                    .clone()
                    .try_into()?;
                Self::Add(cred)
            }
            Proposal::Remove(remove_proposal) => {
                let index = remove_proposal.to_remove().try_into()?;
                if let Some(own_leaf) = context.own_leaf {
                    // If a roster was given, we deduce the value of the device ID from the leaf index that is being removed
                    let device_id = find_device(context.old_roster, index)?;
                    if index == own_leaf {
                        Self::SelfRemove(device_id)
                    } else {
                        Self::Remove(device_id)
                    }
                } else {
                    // If no roster was given, it means we are removing our own device (in an external commit)
                    Self::SelfRemove(committer.device_id()?)
                }
            }
            Proposal::Update(update_proposal) => {
                // SAFETY: it's fine since context is None only for external commits and they don't contain update proposals
                let mut new_credential: Credential =
                    update_proposal.signing_identity().credential.clone().try_into()?;
                let claimset_diff = Self::compute_credential_diff(&mut new_credential, context.old_roster)?;
                Self::Update {
                    claimset_diff,
                    new_credential,
                }
            }
            Proposal::Psk(psk) => {
                let external_id = psk
                    .external_psk_id()
                    .cloned()
                    .ok_or(MlsError::ImplementationError("resumption psk out of scope"))?;
                Self::PskAdded {
                    reference: mls_types::PskReference::External(external_id.into()),
                }
            }
            Proposal::ExternalInit(_) => {
                let is_first_self_device = context
                    .own_user
                    .map(|own_user|
                    // Whether the device add is the first of the user (meaning the user joined the room and did not just add a device)
                    !context
                        .old_roster
                        .iter_mut()
                        .filter_map(|m| m.credential.user_id().ok())
                        .any(|user_id| &user_id == own_user))
                    .unwrap_or(false);

                if is_first_self_device {
                    Self::SelfExternalInit
                } else {
                    Self::ExternalInit(committer.to_owned())
                }
            }
            Proposal::GroupContextExtensions(_) => Self::GroupContextExtensions,
            Proposal::AppDataUpdate(adu_proposal) => match adu_proposal.op {
                mls_rs::group::proposal::AppDataUpdateOperation::Invalid => {
                    return Err(MlsError::ImplementationError("invalid ApplicationDataUpdate proposal"));
                }
                mls_rs::group::proposal::AppDataUpdateOperation::Update(data) => {
                    Self::compute_adu_proposal_update(context, adu_proposal.component_id, data)?
                }
                mls_rs::group::proposal::AppDataUpdateOperation::Remove => {
                    Self::RemoveComponent(adu_proposal.component_id)
                }
            },
            _ => return Err(MlsError::ImplementationError("unsupported proposal effect mapping")),
        };
        Ok(v)
    }

    fn compute_adu_proposal_update(
        context: ProposalContext,
        component_id: ComponentId,
        data: Vec<u8>,
    ) -> Result<Self, MlsError> {
        Ok(match component_id {
            id if id == RoomMetadata::component_id() => Self::UpdateRoomMetadata {
                metadata: RoomMetadata::from_tls_bytes(&data)?,
            },
            id if id == ParticipantListData::component_id() => {
                let update = ParticipantListUpdate::from_tls_bytes(&data)?;

                if let Some(old_participant_list) = context.old_participant_list {
                    let changed = update
                        .changed_roles_participants
                        .iter()
                        .flat_map(|changed| {
                            old_participant_list
                                .participants
                                .get(changed.user_index as usize)
                                .into_iter()
                                .map(|participant| {
                                    Ok::<_, ProtonMeetIdError>(UserIdRolePair {
                                        user: UserId::try_from(&*participant.user)?,
                                        role: UserRole::from_index(changed.role_index),
                                    })
                                })
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let removed = update
                        .removed_indices
                        .iter()
                        .filter_map(|index| {
                            old_participant_list
                                .participants
                                .get(*index as usize)
                                // if we were removing an invalid index, the proposal would have been refused
                                .map(|participant| UserId::try_from(&*participant.user))
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let added = update
                        .added_participants
                        .into_iter()
                        .map(|UserRolePair { user, role_index }| {
                            Ok::<_, ProtonMeetIdError>(UserIdRolePair {
                                user: UserId::try_from(&*user)?,
                                role: UserRole::from_index(role_index),
                            })
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    Self::UpdateParticipantList {
                        participants: ParticipantListEffect {
                            changed,
                            removed,
                            added,
                        },
                    }
                } else {
                    Self::UpdateParticipantList {
                        participants: ParticipantListEffect::default(),
                    }
                }
            }
            _ => Self::UpdateComponent { id: component_id, data },
        })
    }

    fn compute_credential_diff(new_cred: &mut Credential, old_roster: &mut [Member]) -> MlsResult<ClaimsetDiff> {
        let user_id = new_cred.user_id()?;
        let user_id = user_id.as_ref();

        let old_claimset = old_roster
            .iter_mut()
            .filter_map(|m| {
                m.device_id()
                    .map(|device_id| device_id.owning_identity_id() == user_id)
                    .unwrap_or_default()
                    .then(|| m.credential.clone().claimset().ok())
                    .flatten()
            })
            .collect::<Vec<_>>();
        let new_claimset = new_cred.claimset()?;
        Ok(ClaimsetDiff::compute(&new_claimset, &old_claimset))
    }
}
