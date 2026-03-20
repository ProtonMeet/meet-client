use std::collections::HashSet;

use meet_identifiers::Epoch;
use crate::meet_policy::UserRole;

use crate::{
    MlsResult,
    mimi_protocol_mls::{ParticipantListUpdate, UserIdentifier, UserRolePair, UserindexRolePair},
    mimi_room_policy::{
        AppDataPolicyExt,
        authorizer::AuthorizerError,
        policy::ClaimExtractor,
        spec::{
            preauth::{Claim, ClaimId},
            rbac::StdCapability,
        },
    },
    mls_spec::{
        defs::CredentialType,
        drafts::mls_extensions::safe_application::{ApplicationDataDictionary, Component as _, ComponentData},
    },
};
use proton_claims::reexports::{ClaimName, CwtAny, Query, QueryElement};

/// authorization related information on a user, employed in UI
#[derive(Debug, Clone, Default)]
pub struct UserAuthorizationInfo {
    pub role: UserRole,
    /// can I remove this user?
    pub can_be_removed: bool,
    /// can I promote this user channel manager?
    pub can_be_promoted_channel_manager: bool,
    /// can I demote this user simple member?
    pub can_be_demoted_member: bool,
}

pub fn authorization_info(
    authorizer: &Authorizer,
    epoch: Epoch,
    user_identity: &UserIdentifier,
    active_participants: &HashSet<UserIdentifier>,
    is_self: bool,
) -> MlsResult<UserAuthorizationInfo> {
    let role = authorizer.role_for_user(*epoch, user_identity)?;

    let can_be_removed = authorizer
        .can_remove_user(*epoch, user_identity, active_participants)
        .is_ok();

    let can_change_role = |role_index: u32| {
        if is_self {
            authorizer
                .can_change_own_role(*epoch, role_index, active_participants)
                .is_ok()
        } else {
            authorizer
                .can_change_role(*epoch, user_identity, role_index, active_participants)
                .is_ok()
        }
    };
    let role = UserRole::from_index(role.role_index);

    Ok(UserAuthorizationInfo {
        role,
        can_be_promoted_channel_manager: can_change_role(UserRole::RoomAdmin as u32),
        can_be_demoted_member: can_change_role(UserRole::Member as u32),
        can_be_removed,
    })
}

pub use crate::mimi_room_policy::authorizer::Authorizer;

pub trait AuthorizerExt {
    fn retain_recent_epochs(&mut self, current_epoch: EpochIndex);

    fn role_proposal_for_added_user(
        &self,
        epoch: u64,
        user_identity: UserIdentifier,
        target_user_role: UserRole,
    ) -> MlsResult<Option<ComponentData>>;

    fn role_proposal_for_removed_user(
        &self,
        epoch: u64,
        user_identity: &UserIdentifier,
        active_participants: &HashSet<UserIdentifier>,
    ) -> MlsResult<Option<ComponentData>>;

    fn participant_update_for_removed_user(
        &self,
        epoch: u64,
        user_identity: &UserIdentifier,
        active_participants: &HashSet<UserIdentifier>,
    ) -> MlsResult<Option<ParticipantListUpdate>>;

    fn role_proposal_for_changed_user(
        &self,
        epoch: u64,
        user_identity: UserIdentifier,
        role_index: u32,
        active_participants: &HashSet<UserIdentifier>,
    ) -> MlsResult<Option<ComponentData>>;

    fn participant_update_for_changed_user(
        &self,
        epoch: u64,
        user_identity: UserIdentifier,
        role_index: u32,
        active_participants: &HashSet<UserIdentifier>,
    ) -> MlsResult<Option<ParticipantListUpdate>>;
}

impl AuthorizerExt for Authorizer {
    fn retain_recent_epochs(&mut self, current_epoch: EpochIndex) {
        self.remove_older_epochs(current_epoch.saturating_sub(crate::MAX_EPOCH_RETENTION as u64));
    }

    fn role_proposal_for_added_user(
        &self,
        epoch: u64,
        user_identity: UserIdentifier,
        target_user_role: UserRole,
    ) -> MlsResult<Option<ComponentData>> {
        if let Some(target_role) = self
            .authorized_role_changes_for_user(epoch, &user_identity)?
            .iter()
            .find(|&&user_role| user_role == target_user_role as u32)
        {
            let update = ParticipantListUpdate {
                added_participants: vec![UserRolePair {
                    user: user_identity,
                    role_index: *target_role,
                }],
                changed_roles_participants: vec![],
                removed_indices: vec![],
            };
            let component = update.to_component_data()?;
            Ok(Some(component))
        } else {
            Ok(None)
        }
    }

    fn role_proposal_for_removed_user(
        &self,
        epoch: u64,
        user_identity: &UserIdentifier,
        active_participants: &HashSet<UserIdentifier>,
    ) -> MlsResult<Option<ComponentData>> {
        self.participant_update_for_removed_user(epoch, user_identity, active_participants)
            .and_then(|opt| Ok(opt.map(|update| update.to_component_data()).transpose()?))
    }

    fn participant_update_for_removed_user(
        &self,
        epoch: u64,
        user_identity: &UserIdentifier,
        active_participants: &HashSet<UserIdentifier>,
    ) -> MlsResult<Option<ParticipantListUpdate>> {
        if self.can_remove_user(epoch, user_identity, active_participants).is_ok()
            && let Some(user_index) = self.participant_list_index(epoch, user_identity)?
        {
            let update = ParticipantListUpdate {
                added_participants: vec![],
                changed_roles_participants: vec![],
                removed_indices: vec![user_index],
            };

            return Ok(Some(update));
        }

        Ok(None)
    }

    fn role_proposal_for_changed_user(
        &self,
        epoch: u64,
        user_identity: UserIdentifier,
        role_index: u32,
        active_participants: &HashSet<UserIdentifier>,
    ) -> MlsResult<Option<ComponentData>> {
        self.participant_update_for_changed_user(epoch, user_identity, role_index, active_participants)
            .and_then(|opt| Ok(opt.map(|update| update.to_component_data()).transpose()?))
    }

    fn participant_update_for_changed_user(
        &self,
        epoch: u64,
        user_identity: UserIdentifier,
        role_index: u32,
        active_participants: &HashSet<UserIdentifier>,
    ) -> MlsResult<Option<ParticipantListUpdate>> {
        if self
            .can_change_role(epoch, &user_identity, role_index, active_participants)
            .is_ok()
            && let Some(user_index) = self.participant_list_index(epoch, &user_identity)?
        {
            let update = ParticipantListUpdate {
                added_participants: vec![],
                changed_roles_participants: vec![UserindexRolePair { user_index, role_index }],
                removed_indices: vec![],
            };

            return Ok(Some(update));
        }
        Ok(None)
    }
}

pub fn role_proposal_for_external_join<Extractor: ClaimExtractor>(
    application_data: ApplicationDataDictionary,
    user_identity: &UserIdentifier,
    credential: &Extractor,
    active_participants: HashSet<UserIdentifier>,
) -> MlsResult<Option<ComponentData>> {
    let validation_context = application_data.extract_validation_context()?;

    // If the current user is in the participant list, no need to add a role
    if validation_context
        .participant_list
        .participants
        .iter()
        .any(|pair| pair.user == *user_identity)
    {
        return Ok(None);
    }

    let participants: Vec<_> = validation_context
        .participant_list
        .participants
        .iter()
        .map(|pair| &pair.user)
        .collect();

    // check if the user can get a preauth role
    if let Some(role_index) = validation_context.preauth.get_role(credential) {
        let role = validation_context
            .roles
            .get_role(&role_index)
            .ok_or(AuthorizerError::ReferencingNonExistingRole(role_index))?;

        let can_use_invite_code = role.role_capabilities.contains(&*StdCapability::CanUseJoinCode);
        let can_join_if_preauth = role.role_capabilities.contains(&*StdCapability::CanJoinIfPreauthorized);
        let role_change_authorized = role
            .authorized_role_changes
            .iter()
            .any(|change| change.from_role_index == 0 && change.target_role_indexes.contains(&role_index));

        if (can_use_invite_code || can_join_if_preauth) && role_change_authorized {
            role.can_add(&participants, &active_participants, false)?;

            let update = ParticipantListUpdate {
                added_participants: vec![UserRolePair {
                    user: user_identity.clone(),
                    role_index,
                }],
                changed_roles_participants: vec![],
                removed_indices: vec![],
            };
            let component = update.to_component_data()?;
            Ok(Some(component))
        } else {
            Ok(None)
        }
    } else {
        // no preauth role, so we use the default role index (0)
        let current_role = validation_context
            .roles
            .get_role(&UserRole::NoRole.into())
            .ok_or(AuthorizerError::ReferencingNonExistingRole(0))?;
        current_role.check_capability(&StdCapability::CanOpenJoin)?;
        if let Some(target_role_index) = current_role.authorized_role_changes.iter().find_map(|change| {
            if UserRole::from_index(change.from_role_index) == UserRole::NoRole {
                change.target_role_indexes.iter().max()
            } else {
                None
            }
        }) {
            let target_role = validation_context
                .roles
                .get_role(target_role_index)
                .ok_or(AuthorizerError::ReferencingNonExistingRole(0))?;
            target_role.can_add(&participants, &active_participants, false)?;

            // FIXME: check the max participants
            let update = ParticipantListUpdate {
                added_participants: vec![UserRolePair {
                    user: user_identity.clone(),
                    role_index: *target_role_index,
                }],
                changed_roles_participants: vec![],
                removed_indices: vec![],
            };
            let component = update.to_component_data()?;
            Ok(Some(component))
        } else {
            Ok(None)
        }
    }
}

type EpochIndex = u64;

pub fn preauth_claim_id(claim_name: ClaimName) -> MlsResult<ClaimId> {
    let id = Query::from(vec![QueryElement::ClaimName(claim_name)]).to_cbor_bytes()?;
    let credential_type = CredentialType::new_unchecked(CredentialType::SD_CWT_CREDENTIAL);
    Ok(ClaimId { credential_type, id })
}

pub fn preauth_claim_condition<V: CwtAny>(claim_name: ClaimName, value: V) -> MlsResult<Claim> {
    Ok(Claim {
        claim_id: preauth_claim_id(claim_name)?,
        claim_value: value.to_cbor_bytes()?,
    })
}
