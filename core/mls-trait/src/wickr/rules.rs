use crate::meet_policy::UserRole;
use crate::mimi_protocol_mls::{
    ParticipantListData, ParticipantListUpdate, UserIdentifier,
    reexports::mls_spec::{
        Parsable as _, Serializable as _,
        drafts::mls_extensions::safe_application::{
            AppComponents, AppDataUpdate, ApplicationDataDictionary, ApplicationDataUpdateOperation, Component,
            ComponentId, SafeAadComponent,
        },
    },
};
use crate::mimi_room_policy::{
    AppDataPolicyExt as _, MimiPolicyError, PolicyValidationContext, PolicyValidationContextRef,
    authorizer::AuthorizerError,
    policy::ClaimExtractor,
    spec::{
        preauth::PreAuthData,
        rbac::{Role, RoleData, StdCapability},
    },
};
use crate::{
    MlsClientConfig,
    error::MlsError,
    wickr::{
        error::WickrProviderError,
        identity::{ProtonMeetClaimExtractor, ProtonMeetIdentityProvider},
    },
};
use identity::{ProtonEd25519SdCwtVerifier, SD_CWT_LEEWAY, SD_KBT_LEEWAY};
use meet_mls::{AnySdKbt, SdKbt};
use mls_rs::identity::CustomCredential;
use mls_rs::{
    ExtensionList, MlsRules,
    client_builder::PaddingMode,
    error::MlsError as WickrMlsError,
    extension::built_in::ExternalSendersExt,
    group::{
        Roster, Sender,
        proposal::{AppDataUpdateOperation, BorrowedProposal},
    },
    identity::basic::BasicIdentityProviderError,
    mls_rules::{CommitDirection, CommitOptions, CommitSource, EncryptionOptions, ProposalBundle, ProposalInfo},
};
use mls_rs_codec::MlsEncode;
use mls_rs_core::{
    error::IntoAnyError,
    group::{GroupContext, Member},
};
use mls_types::{CredentialExt, ExtensionListExt};
use proton_claims::reexports::{CwtAny, ShallowVerifierParams, TimeVerification, Verifier, cose_key_set::CoseKeySet};
use std::{collections::HashSet, sync::Arc};

#[derive(Debug, Clone)]
pub struct ProtonMeetRules {
    mls_rules: Arc<mls_rs::mls_rules::DefaultMlsRules>,
    config: Arc<MlsClientConfig>,
    cks: Arc<CoseKeySet>,
    #[cfg(feature = "test-utils")]
    pub rules_tester: Option<RulesTester>,
}

impl ProtonMeetRules {
    /// Builds a new instance
    #[allow(clippy::new_without_default)]
    pub fn new(config: MlsClientConfig, cks: CoseKeySet) -> Self {
        Self {
            mls_rules: Arc::new(mls_rs::mls_rules::DefaultMlsRules::new()),
            config: Arc::new(config),
            cks: Arc::new(cks),
            #[cfg(feature = "test-utils")]
            rules_tester: None,
        }
    }

    #[allow(clippy::too_many_arguments, clippy::cognitive_complexity, clippy::unused_self)]
    fn authorize_proposal<C: ClaimExtractor>(
        &self,
        app_data: &ApplicationDataDictionary,
        mut sender_sd_kbt: AnySdKbt,
        validation_context: &PolicyValidationContext,
        sender_identity: &UserIdentifier,
        sender_role: &Role,
        extension_list: &ExtensionList,
        roster: &Roster<'_>,
        proposal: &ProposalInfo<BorrowedProposal<'_>>,
        claim_extractor: &C,
        members: &[Member],
        users_with_changed_roles: &mut HashSet<UserIdentifier>,
        required_components: Option<&AppComponents>,
        added_required_components: &Option<HashSet<ComponentId>>,
        source: &CommitSource,
        direction: CommitDirection,
        cks: &CoseKeySet,
        sender: &Sender,
    ) -> Result<bool, MlsError> {
        let PolicyValidationContext {
            roles,
            participant_list,
            preauth,
        } = validation_context;
        let active_participant_identities = members
            .iter()
            .map(|m| &m.signing_identity)
            .map(ProtonMeetIdentityProvider::identity_from_signing_identity)
            .collect::<Result<HashSet<_>, _>>()?;

        Ok(match proposal.proposal {
            BorrowedProposal::Add(add) => {
                let kp = add.key_package();
                let leaf_node = &kp.leaf_node;

                if matches!(direction, CommitDirection::Send) {
                    match &leaf_node.signing_identity.credential {
                        mls_rs::identity::Credential::Custom(CustomCredential {
                            credential_type,
                            data: sd_kbt,
                        }) if *credential_type == mls_spec::defs::CredentialType::SD_CWT_CREDENTIAL.into() => {
                            let params = ShallowVerifierParams {
                                sd_cwt_leeway: SD_CWT_LEEWAY,
                                sd_kbt_leeway: SD_KBT_LEEWAY,
                                sd_cwt_time_verification: TimeVerification {
                                    verify_iat: false, // FIXME: after introducing a leeway in iat
                                    ..Default::default()
                                },
                                sd_kbt_time_verification: TimeVerification {
                                    verify_iat: false, // FIXME: after introducing a leeway in iat
                                    ..Default::default()
                                },
                                artificial_time: None, // this is fine since we verify proposals at creation time. This will resolve to now in case missing
                            };
                            ProtonEd25519SdCwtVerifier.shallow_verify_sd_kbt(sd_kbt, params, None, cks)?;
                        }
                        _ => {}
                    }
                }

                // verify that the new member supports all the required components of the group
                if let Some(app_data) = leaf_node.extensions.application_data_spec()? {
                    let supported_components = app_data.extract_component::<AppComponents>()?;
                    if let Some((supported, required)) = supported_components.zip(required_components) {
                        for r in &required.0.component_ids {
                            if !supported.0.component_ids.contains(r) {
                                return Err(MlsError::MissingRequiredComponent(*r));
                            }
                        }
                    }
                }

                let added_identity: UserIdentifier =
                    ProtonMeetIdentityProvider::identity_from_signing_identity(&leaf_node.signing_identity)?;

                if &added_identity == sender_identity {
                    sender_role.check_capability(&StdCapability::CanAddOwnClient)?;
                    if participant_list.participants.iter().all(|p| p.user != added_identity)
                        && matches!(sender, Sender::NewMemberProposal)
                    {
                        if UserRole::from_index(sender_role.role_index) == UserRole::NoRole {
                            sender_role.check_capability(&StdCapability::CanOpenJoin)?;
                        } else {
                            sender_role.check_capability(&StdCapability::CanJoinIfPreauthorized)?;
                        }
                    }
                } else {
                    // check if the added identity is already in the participant list
                    if let Some(pair) = participant_list.participants.iter().find(|p| p.user == added_identity) {
                        let role = roles
                            .get_role(&pair.role_index)
                            .ok_or(AuthorizerError::ReferencingNonExistingRole(pair.role_index))?;

                        let is_active_participant = active_participant_identities.contains(&added_identity);
                        let role_participants = role.participants(participant_list).collect::<Vec<_>>();

                        //FIXME: check the semantics of can_add for participants already present in the list but adding more devices
                        role.can_add(
                            &role_participants,
                            &active_participant_identities,
                            is_active_participant,
                        )?;
                    } else {
                        sender_role.check_capability(&StdCapability::CanAddParticipant)?;
                    }
                }

                true
            }
            BorrowedProposal::Update(_update) => {
                sender_role.check_capability(&StdCapability::CanSendMlsUpdateProposal)?;
                true
            }
            BorrowedProposal::Remove(r) => {
                let removed_member = roster.member_with_index(r.to_remove())?;

                let removed_identity: UserIdentifier =
                    ProtonMeetIdentityProvider::identity_from_signing_identity(&removed_member.signing_identity)?;

                if &removed_identity == sender_identity {
                    sender_role.check_capability(&StdCapability::CanRemoveSelf)?;
                    return Ok(true);
                }

                sender_role.check_capability(&StdCapability::CanRemoveParticipant)?;

                let removed_role_index = participant_list
                    .participants
                    .iter()
                    .find_map(|pair| {
                        if pair.user == removed_identity {
                            Some(pair.role_index)
                        } else {
                            None
                        }
                    })
                    // the role index for members absent from the participant list is zero
                    .unwrap_or_default();

                // if the removed user already has a role index of zero, we can remove them
                // since we already checked the capability
                if removed_role_index == 0 {
                    return Ok(true);
                }

                sender_role
                    .authorized_role_changes
                    .iter()
                    .find(|change| change.from_role_index == removed_role_index)
                    .is_some_and(|change| change.target_role_indexes.contains(&0))
            }
            BorrowedProposal::Psk(_) => {
                sender_role.check_capability(&StdCapability::CanSendMlsPSKProposal)?;
                true
            }
            BorrowedProposal::ReInit(_re) => {
                sender_role.check_capability(&StdCapability::CanSendMlsReinitProposal)?;
                true
            }
            BorrowedProposal::ExternalInit(_ei) => {
                sender_role.check_capability(&StdCapability::CanSendMlsExternalCommit)?;

                let sender_in_participants_list = participant_list
                    .participants
                    .iter()
                    .any(|rp| &rp.user == sender_identity);

                if sender_in_participants_list {
                    sender_role.check_capability(&StdCapability::CanAddOwnClient)?;
                } else {
                    let capability = if UserRole::from_index(sender_role.role_index) == UserRole::NoRole {
                        StdCapability::CanOpenJoin
                    } else {
                        StdCapability::CanJoinIfPreauthorized
                    };
                    sender_role.check_capability(&capability).map_err(MlsError::from)?;
                }

                // verify that the joiner supports all the required components of the group
                let CommitSource::NewMember(joiner_leaf_node) = source else {
                    return Err(MlsError::ImplementationError(
                        "Invalid CommitSource on a ExternalInit proposal",
                    ));
                };
                let joiner_app_data = joiner_leaf_node.extensions.application_data_spec()?.unwrap_or_default();
                if let Some(supported_components) = joiner_app_data
                    .extract_component::<AppComponents>()?
                    .as_ref()
                    .map(|c| c.0.component_ids.iter().copied().collect::<HashSet<_>>())
                {
                    // FIXME: should use the interim group_context once provided by mls-rs
                    if let Some(required_components) = required_components {
                        let required_components = required_components
                            .0
                            .component_ids
                            .iter()
                            .copied()
                            .collect::<HashSet<_>>();
                        let missing = required_components
                            .difference(&supported_components)
                            .copied()
                            .collect::<Vec<_>>();

                        if !missing.is_empty() {
                            return Err(MlsError::MissingRequiredComponents(missing));
                        }
                    }
                } else {
                    let has_some_required_components = required_components
                        .map(|c| !c.0.component_ids.is_empty())
                        .unwrap_or_default();
                    if has_some_required_components {
                        // and the new leaf node does not support any component
                        // then the 'AppComponents' itself is missing
                        return Err(MlsError::MissingRequiredComponent(AppComponents::component_id()));
                    }
                }

                true
            }
            BorrowedProposal::GroupContextExtensions(gce) => {
                extension_list.application_data_spec()? == gce.application_data_spec()?
            }
            BorrowedProposal::AppEphemeral(_) => {
                // AppEphemeral proposals are only attaching data to a commit and do not modify shared state
                true
            }
            BorrowedProposal::AppDataUpdate(update) => {
                let app_data_update = AppDataUpdate::from_tls_bytes(&update.mls_encode_to_vec()?[..])?;
                match app_data_update {
                    AppDataUpdate { component_id: id, .. }
                        if id == ParticipantListData::component_id()
                            || id == RoleData::component_id()
                            || id == PreAuthData::component_id() =>
                    {
                        let ctx = PolicyValidationContextRef {
                            roles,
                            participant_list,
                            preauth,
                        };
                        ctx.authorize_room_policy_update(
                            sender_identity,
                            app_data_update,
                            claim_extractor,
                            sender_role,
                            &active_participant_identities,
                            users_with_changed_roles,
                        )?;
                    }
                    AppDataUpdate {
                        component_id: id,
                        op: ApplicationDataUpdateOperation::Update { .. },
                    } if id == AppComponents::component_id() => {
                        // if new required components were added verify they are supported by all the members
                        if let Some(added_required_components) = added_required_components {
                            for m in members {
                                let supported_components = m
                                    .extensions
                                    .application_data_spec()?
                                    .and_then(|a| a.extract_component::<AppComponents>().transpose())
                                    .transpose()?
                                    .map(|c| c.0.component_ids)
                                    .unwrap_or_default();

                                for added in added_required_components {
                                    if !supported_components.contains(added) {
                                        return Err(MlsError::UnsupportedComponent(*added));
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                };
                true
            }
            BorrowedProposal::Custom(_) => {
                // we cannot authorize proposals we don't know
                false
            }
        })
    }
}

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum ProposalValidationError {
    #[error("Unauthorized")]
    Unauthorized,
    #[error("{0}")]
    Mls(#[from] WickrMlsError),
    #[error("{0}")]
    MlsCodec(#[from] mls_rs::mls_rs_codec::Error),
    #[error("{0}")]
    Idp(#[from] BasicIdentityProviderError),
    #[error("{0}")]
    SdCwt(#[from] proton_claims::reexports::EsdicawtSpecError),
    #[error("Default")]
    Default,
}

impl IntoAnyError for ProposalValidationError {}

impl From<WickrMlsError> for WickrProviderError {
    fn from(value: WickrMlsError) -> Self {
        Self::Proposal(ProposalValidationError::Mls(value))
    }
}

#[maybe_async::must_be_async]
impl MlsRules for ProtonMeetRules {
    type Error = MlsError;

    async fn filter_proposals(
        &self,
        direction: CommitDirection,
        source: CommitSource,
        current_roster: &Roster,
        current_context: &GroupContext,
        proposals: ProposalBundle,
    ) -> Result<ProposalBundle, Self::Error> {
        let Some(app_data) = current_context.extensions.application_data_spec()? else {
            //no existing application data, so no room policies, so accept all proposals
            return Ok(proposals);
        };

        let mut active_participants = current_roster.members();

        // holds the list of users for whom we change roles in the proposals, to make sure
        // there are no conflicting updates
        let mut users_with_changed_roles = HashSet::new();

        let mut added_required_components = None;

        let validation_context = app_data.extract_validation_context()?;
        let mut required_app_components = app_data.extract_component::<AppComponents>()?;

        for proposal in proposals.iter_proposals_for_applying() {
            let is_external = !matches!(&proposal.sender, Sender::Member(_));

            // https://www.rfc-editor.org/rfc/rfc9420.html#name-content-authentication
            let sender_signing_identity = match proposal.sender {
                Sender::Member(index) => current_roster.member_with_index(index)?.signing_identity,
                Sender::External(index) => current_context
                    .extensions()
                    .get_as::<ExternalSendersExt>()
                    .ok()
                    .flatten()
                    .and_then(|ext| ext.allowed_senders.get(index as usize).cloned())
                    .ok_or_else(|| WickrProviderError::Proposal(ProposalValidationError::Unauthorized))?,
                Sender::NewMemberProposal => {
                    if let BorrowedProposal::Add(add) = proposal.proposal {
                        add.signing_identity().clone()
                    } else {
                        return Err(WickrProviderError::Proposal(ProposalValidationError::Unauthorized).into());
                    }
                }
                Sender::NewMemberCommit => {
                    if let CommitSource::NewMember(leaf_node) = &source {
                        leaf_node.signing_identity.clone()
                    } else {
                        return Err(WickrMlsError::ExternalCommitMustHaveNewLeaf.into());
                    }
                }
                _ => {
                    //unknown sender type
                    return Err(WickrProviderError::Proposal(ProposalValidationError::Unauthorized).into());
                }
            };

            let sender_identity = ProtonMeetIdentityProvider::identity_from_signing_identity(&sender_signing_identity)?;

            let sender_sd_kbt = sender_signing_identity
                .credential
                .as_sd_cwt()
                .ok_or_else(|| MlsError::ImplementationError("Unsupported credential type"))?;
            let mut sender_sd_kbt = SdKbt::from_cbor_bytes(sender_sd_kbt)?;
            let sender_sd_kbt = AnySdKbt::Unverified(&mut sender_sd_kbt);

            let claim_extractor = ProtonMeetClaimExtractor::new(sender_signing_identity.credential)?;
            let sender_role =
                validation_context
                    .as_ref()
                    .get_sender_role(&sender_identity, &claim_extractor, is_external)?;

            match &proposal.sender {
                Sender::External(_) | Sender::NewMemberProposal => {
                    sender_role.check_capability(&StdCapability::CanSendMlsExternalProposal)?
                }
                Sender::NewMemberCommit => sender_role.check_capability(&StdCapability::CanSendMlsExternalCommit)?,
                _ => {}
            };

            match proposal.proposal {
                BorrowedProposal::Remove(p) => active_participants.retain(|m| m.index != p.to_remove()),
                BorrowedProposal::AppDataUpdate(mls_rs::group::proposal::AppDataUpdateProposal {
                    component_id,
                    op: AppDataUpdateOperation::Update(update),
                }) if component_id == &AppComponents::component_id() => {
                    let raw_new_app_components = AppComponents::from_tls_bytes(&update[..])?;
                    let new_app_components = raw_new_app_components
                        .0
                        .component_ids
                        .iter()
                        .copied()
                        .collect::<HashSet<_>>();

                    if let Some(old_app_components) = &required_app_components {
                        let old_app_components = old_app_components
                            .0
                            .component_ids
                            .iter()
                            .copied()
                            .collect::<HashSet<_>>();
                        let diff = new_app_components
                            .difference(&old_app_components)
                            .copied()
                            .collect::<HashSet<_>>();
                        added_required_components.replace(diff);
                    } else {
                        // if there are no previous required components the update is the new required components
                        added_required_components.replace(new_app_components);
                    }

                    // we swap the required components ahead of tim(e before doing our proposal validation)
                    // in order to account for cases where a component is not required anymore which
                    // would authorize an Add proposal for a member without this component
                    required_app_components.replace(raw_new_app_components);
                }
                _ => {}
            };

            if !self.authorize_proposal(
                &app_data,
                sender_sd_kbt,
                &validation_context,
                &sender_identity,
                &sender_role,
                &current_context.extensions,
                current_roster,
                &proposal,
                &claim_extractor,
                &active_participants,
                &mut users_with_changed_roles,
                required_app_components.as_ref(),
                &added_required_components,
                &source,
                direction,
                &self.cks,
                &proposal.sender,
            )? {
                return Err(WickrProviderError::Proposal(ProposalValidationError::Unauthorized).into());
            }
        }

        Ok(proposals)
    }

    fn commit_options(
        &self,
        new_roster: &Roster,
        new_context: &GroupContext,
        proposals: &ProposalBundle,
    ) -> Result<CommitOptions, Self::Error> {
        Ok(self
            .mls_rules
            .commit_options(new_roster, new_context, proposals)
            .map_err(|_| Self::Error::ImplementationError("default rules in mls-rs failed"))?
            .with_ratchet_tree_extension(false)
            .with_single_welcome_message(true)
            .with_path_required(false)
            .with_allow_external_commit(true))
    }

    fn encryption_options(
        &self,
        _current_roster: &Roster,
        _current_context: &GroupContext,
    ) -> Result<EncryptionOptions, Self::Error> {
        Ok(EncryptionOptions::new(false, PaddingMode::Padme))
    }

    fn supported_components(&self) -> &[mls_rs::group::ComponentId] {
        &self.config.supported_app_components.0.component_ids
    }

    fn validate_component_data(&self, _component_id: mls_rs::group::ComponentId, _component_data: &[u8]) -> bool {
        false
    }

    async fn update_components(
        &self,
        component_id: mls_rs::group::ComponentId,
        component_data: Option<&[u8]>,
        update: &[u8],
        _roster: &Roster,
    ) -> Result<Vec<u8>, Self::Error> {
        match component_id {
            id if id == RoleData::component_id() => {
                let _ = RoleData::from_tls_bytes(update)?;
                // if it deserializes correctly, we can update the roles
                Ok(update.to_owned())
            }
            id if id == ParticipantListData::component_id() => {
                let mut current_participants: ParticipantListData = component_data
                    .map(ParticipantListData::from_tls_bytes)
                    .transpose()?
                    .unwrap_or_default();

                let _removed = current_participants
                    .apply_update(ParticipantListUpdate::from_tls_bytes(update)?)
                    .map_err(|index| {
                        MimiPolicyError::from(AuthorizerError::ReferencingNonExistingParticipant(index))
                    })?;

                let data = current_participants.to_tls_bytes()?;
                Ok(data)
            }
            id if id == PreAuthData::component_id() => {
                let _ = PreAuthData::from_tls_bytes(update)?;
                // if it deserializes correctly, we can update the preauth data
                Ok(update.to_owned())
            }
            id if id == AppComponents::component_id() => {
                let _ = AppComponents::from_tls_bytes(update)?;
                // if it deserializes correctly, we can update the preauth data
                Ok(update.to_owned())
            }
            id if id == SafeAadComponent::component_id() => {
                let _ = SafeAadComponent::from_tls_bytes(update)?;
                // if it deserializes correctly, we can update the preauth data
                Ok(update.to_owned())
            }
            #[cfg(feature = "test-utils")] // for unit tests
            id if id == 0xFFAB => Ok(update.to_owned()),
            _ => Err(WickrProviderError::Proposal(ProposalValidationError::Unauthorized).into()),
        }
    }
}

#[cfg(feature = "test-utils")]
#[derive(Default, Debug, Clone)]
pub struct RulesTester {
    #[allow(clippy::type_complexity)]
    pub validate_preauth: Option<fn(&PreAuthData, &PreAuthData, &UserIdentifier, &Role) -> crate::MlsResult<()>>,
}
