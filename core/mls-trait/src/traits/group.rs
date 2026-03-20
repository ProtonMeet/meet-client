// re-exports
#[cfg(feature = "wickr")]
pub use crate::wickr::group::MlsGroup;
use proton_claims::Role as ProtonRole;

use crate::{
    Authorizer, MlsError, MlsResult, SenderReInitOutput,
    mimi_protocol_mls::{
        ParticipantListData, ParticipantListUpdate, UserIdentifier, UserindexRolePair,
        components::metadata::RoomMetadata,
    },
    mimi_room_policy::{
        authorizer::AuthorizerError,
        spec::{
            preauth::{Claim, PreAuthData, PreAuthRoleEntry},
            rbac::{Role, RoleData, StdCapability},
        },
    },
    mls_spec,
    types::{
        Caniuse, CommitBundle, CommitOutput, ProposalArg, ReceivedMessage, ReceivedMessages, ReceiverReInitOutput,
    },
};
use mls_spec::{
    defs::{ExtensionType, ProposalType},
    drafts::mls_extensions::safe_application::Component,
    drafts::mls_extensions::safe_application::{AppComponents, ComponentId, SafeAadComponent},
    group::ExternalSender,
};

use crate::meet_policy::UserRole;
use itertools::Itertools;
use meet_identifiers::{DeviceId, Epoch, GroupId, Identifier, LeafIndex, RoomId, UserId};
use mls_types::{
    Capabilities, CipherSuite, Credential, CredentialType, Extensions, HashAlgorithm, KeyPackage, LeafNode, MediaType,
    Member, MlsMessage, MlsTypesResult, ProtocolVersion, PublicRatchetTree, Secret, Sender, SigningIdentity,
    get_component,
};
use std::collections::HashMap;

#[allow(private_bounds, async_fn_in_trait)]
pub trait MlsGroupTrait {
    fn id(&self) -> MlsResult<GroupId>;

    fn room_id(&self) -> MlsResult<RoomId>;

    async fn encrypt_messages<M>(
        &mut self,
        user_messages: impl IntoIterator<Item = (MediaType, M)>,
    ) -> MlsResult<Vec<MlsMessage>>
    where
        M: Into<Vec<u8>>;

    async fn encrypt_message(&mut self, media_type: MediaType, user_message: &[u8]) -> MlsResult<MlsMessage>;

    #[allow(refining_impl_trait)]
    async fn decrypt_messages(
        &mut self,
        messages: impl IntoIterator<Item: Into<MlsMessage>>,
    ) -> MlsResult<(
        ReceivedMessages,
        Option<ReceiverReInitOutput<impl MlsGroupPendingReInitTrait + Clone>>,
    )>;

    #[allow(refining_impl_trait)]
    async fn decrypt_message(
        &mut self,
        messages: impl Into<MlsMessage>,
    ) -> MlsResult<(
        ReceivedMessage,
        Option<ReceiverReInitOutput<impl MlsGroupPendingReInitTrait + Clone>>,
    )>;

    async fn new_proposals(&mut self, proposals: impl IntoIterator<Item = ProposalArg>) -> MlsResult<Vec<MlsMessage>>;

    /// The returned boolean is true whether the commit contains proposals by reference
    async fn new_commit(&mut self, proposals: impl IntoIterator<Item = ProposalArg>)
    -> MlsResult<(CommitBundle, bool)>;

    #[allow(refining_impl_trait)]
    async fn merge_pending_commit(
        &mut self,
    ) -> MlsResult<(
        CommitOutput,
        Option<SenderReInitOutput<impl MlsGroupPendingReInitTrait + Clone>>,
    )>;

    fn clear_pending_commit(&mut self);

    fn protocol_version(&self) -> MlsResult<ProtocolVersion>;

    #[allow(clippy::type_complexity)]
    fn reinit_proposal(
        &mut self,
        new_ciphersuite: Option<CipherSuite>,
        new_protocol_version: Option<ProtocolVersion>,
    ) -> MlsResult<(Option<Vec<u8>>, ProtocolVersion, CipherSuite, Extensions)> {
        let new_group_id = GroupId::new(&self.id()?.domain).to_bytes();

        let new_ciphersuite = new_ciphersuite.unwrap_or(self.ciphersuite()?);

        let current_protocol_version = self.protocol_version()?;
        let new_protocol_version = new_protocol_version
            .and_then(|npv| (npv != current_protocol_version).then_some(npv))
            .unwrap_or(current_protocol_version);

        let new_extensions = self.extensions()?;

        Ok((
            Some(new_group_id),
            new_protocol_version,
            new_ciphersuite,
            new_extensions,
        ))
    }

    fn find_member(&self, index: LeafIndex) -> MlsResult<Member>;

    fn find_sender(&self, sender: &Sender) -> MlsResult<Option<Credential>>;

    fn member_index(&self, cred: &mut Credential) -> MlsResult<LeafIndex>;

    fn own_leaf_index(&self) -> MlsResult<LeafIndex>;

    fn own_leaf_node(&self) -> MlsResult<LeafNode>;

    fn own_signing_identity(&self) -> MlsResult<SigningIdentity> {
        Ok(self.own_leaf_node()?.signing_identity.try_into()?)
    }

    fn own_credential(&self) -> MlsResult<Credential> {
        Ok(self.own_signing_identity()?.credential)
    }

    fn own_device_id(&self) -> MlsResult<DeviceId> {
        Ok(self.own_credential()?.device_id()?)
    }

    fn own_user_id(&self) -> MlsResult<UserId> {
        Ok(self.own_credential()?.user_id()?)
    }

    fn epoch(&self) -> Epoch;

    fn application_data(&self) -> MlsResult<Option<mls_rs::group::ApplicationDataDictionary>>;

    fn name(&self) -> MlsResult<Option<String>> {
        Ok(self
            .extract_component::<RoomMetadata>()?
            .map(|rm| rm.room_name.string)
            .filter(|name| !name.is_empty()))
    }

    fn participant_list(&self) -> MlsResult<Option<ParticipantListData>> {
        self.extract_component::<ParticipantListData>()
    }

    /// retrieve the associated room metadata
    fn get_metadata(&self) -> MlsResult<RoomMetadata> {
        self.extract_component::<RoomMetadata>()?
            .ok_or(MlsError::MissingRoomMetadata)
    }

    fn roster(&self) -> impl Iterator<Item = Member>;

    fn user_roster(&self) -> MlsResult<HashMap<UserId, Vec<Member>>> {
        Ok(self
            .roster()
            .filter_map(|mut m| m.user_id().ok().map(|id| (m, id)))
            .chunk_by(|(_, uid)| uid.clone())
            .into_iter()
            .map(|(k, v)| (k, v.map(|(m, _)| m).collect()))
            .collect())
    }

    fn has_user_in_roster(&self, user_id: &UserId) -> MlsResult<bool> {
        use meet_identifiers::ByRef as _;
        Ok(self
            .all_device_ids()
            .any(|id| id.owning_identity_id() == user_id.as_ref()))
    }

    fn has_user_in_participant_list(&self, user_id: &UserId) -> MlsResult<bool> {
        Ok(self.participant_list()?.is_some_and(|list| {
            list.participants
                .iter()
                .any(|p| p.user == UserIdentifier::from(user_id.to_string()))
        }))
    }

    fn roster_leaf_indexes(&self) -> MlsResult<Vec<LeafIndex>>;

    fn all_user_ids(&self) -> MlsResult<HashMap<CredentialType, UserId>> {
        Ok(self
            .roster()
            .map(|mut m| m.user_id().map(|id| (m.credential_type(), id)))
            .collect::<MlsTypesResult<_>>()?)
    }

    fn all_device_ids(&self) -> impl Iterator<Item = DeviceId>;

    fn find_admin(&self, skip: Vec<UserId>) -> MlsResult<Option<UserId>> {
        Ok(self.roster().into_iter().find_map(|mut m| {
            let user_id = m.user_id().ok()?;
            let should_skip = skip.contains(&user_id);
            if m.workspace_role() == ProtonRole::OrganizationAdmin && !should_skip {
                m.user_id().ok()
            } else {
                None
            }
        }))
    }

    fn pending_proposals(&self) -> MlsResult<Vec<mls_types::Proposal>>;

    fn clear_pending_proposals(&mut self);

    fn has_pending_commit(&self) -> bool;

    fn ciphersuite(&self) -> MlsResult<CipherSuite>;

    fn hash_algorithm(&self) -> MlsResult<HashAlgorithm>;

    /// Extract a GroupInfo from a Group that holds no
    /// `ExternalPub` Extension allowing External Commits
    ///
    /// This is needed and used specifically for extracting
    /// the GroupInfo of Epoch 0 to add it to the Epoch 0->1
    /// Commit's SafeAAD
    async fn bare_group_info_no_ext_commit(&self) -> MlsResult<MlsMessage>;

    async fn group_info_for_ext_commit(&self) -> MlsResult<MlsMessage>;

    fn ratchet_tree(&self) -> mls_rs::group::ExportedTree<'static>;

    fn extensions(&self) -> MlsResult<mls_types::Extensions>;

    fn external_senders(&self) -> MlsResult<Option<Vec<ExternalSender>>> {
        let extensions = self.extensions()?;
        Ok(extensions.external_senders().map(|s| s.to_vec()))
    }

    fn application_data_spec(
        &self,
    ) -> MlsResult<Option<mls_spec::drafts::mls_extensions::safe_application::ApplicationDataDictionary>> {
        Ok(self.extensions()?.app_data().cloned())
    }

    fn extract_component<C: Component>(&self) -> MlsResult<Option<C>> {
        Ok(self
            .application_data_spec()?
            .and_then(|app_data| app_data.extract_component::<C>().transpose())
            .transpose()?)
    }

    /// generate proposals to update the room metadata
    fn update_metadata(&self, metadata: RoomMetadata) -> MlsResult<ProposalArg>;
    /// generate a proposal to change an existing user's role
    fn update_participant_role(&self, user_index: u32, user_role: UserRole) -> MlsResult<ProposalArg> {
        let participants: ParticipantListUpdate = ParticipantListUpdate {
            removed_indices: vec![],
            changed_roles_participants: vec![UserindexRolePair {
                user_index,
                role_index: user_role as u32,
            }],
            added_participants: vec![],
        };

        ProposalArg::update_component(&participants)
    }

    /// generate a proposal to add a new preauth entry
    async fn add_preauth_proposals(&mut self, claims: Vec<Claim>, user_role: UserRole) -> MlsResult<Vec<MlsMessage>> {
        let proposal = self.new_preauth_proposal(claims, user_role)?;
        self.new_proposals([proposal]).await
    }

    fn new_preauth_proposal(&self, claimset: Vec<Claim>, user_role: UserRole) -> MlsResult<ProposalArg> {
        let application_data = self.application_data()?.unwrap_or_default();
        let mut preauth = get_component::<PreAuthData>(&application_data)?.unwrap_or_default();
        let Some(roles) = get_component::<RoleData>(&application_data)? else {
            return Err(AuthorizerError::MissingRoleData.into());
        };
        let Some(target_role) = roles.get_role(&(user_role as u32)).cloned() else {
            return Err(AuthorizerError::ReferencingNonExistingRole(user_role as u32).into());
        };

        preauth
            .preauthorized_entries
            .push(PreAuthRoleEntry { claimset, target_role });
        ProposalArg::update_component(&preauth)
    }

    fn new_role_proposal(&self, role: Role) -> MlsResult<ProposalArg> {
        let application_data = self.application_data()?.unwrap_or_default();
        let Some(mut role_data) = get_component::<RoleData>(&application_data)? else {
            return Err(MlsError::ImplementationError(
                "No existing roles in this room, strange...",
            ));
        };
        if role_data.insert_role(role).is_some() {
            tracing::warn!("[BUG] Incorrect usage of 'new_role_proposal', role already exists")
        }
        ProposalArg::update_component(&role_data)
    }

    fn update_role_proposal(&self, role: Role) -> MlsResult<ProposalArg> {
        let application_data = self.application_data()?.unwrap_or_default();
        let Some(mut role_data) = get_component::<RoleData>(&application_data)? else {
            return Err(MlsError::ImplementationError(
                "No existing roles in this room, strange...",
            ));
        };
        if role_data.insert_role(role).is_none() {
            tracing::warn!("[BUG] Incorrect usage of 'update_role_proposal', role doesn't already exist")
        }
        ProposalArg::update_component(&role_data)
    }

    fn users_about_to_be_removed(&self, proposals: &[ProposalArg]) -> MlsResult<Vec<UserId>>;

    fn authorizer(&self) -> MlsResult<Authorizer>;

    fn check_capability(&self, capability: StdCapability) -> MlsResult<()> {
        if self.authorizer()?.check_capability(*self.epoch(), *capability)? {
            Ok(())
        } else {
            Err(MlsError::UnauthorizedCapability(capability))
        }
    }
    /// returns the MLS identity for a given credential, as defined by `ProtonMeetIdentityProvider`
    fn member_identity(&self, credential: &Credential) -> MlsResult<UserIdentifier>;

    /// Export a secret from the MLS KeySchedule
    async fn export_secret(&self, label: &'static str, context: &[u8], len: usize) -> MlsResult<Secret>;

    fn epoch_authenticator(&self) -> MlsResult<Secret>;

    /// Returns true if all the clients in the group supports the proposal
    fn caniuse_proposals(&self, pt: &[ProposalType]) -> MlsResult<Caniuse> {
        // if all are default
        if pt.iter().all(|p| p.is_spec_default()) {
            return Ok(Caniuse::Yes);
        }
        // if it's in the required capabilities it means all the MLS client HAVE TO support it
        let extensions = self.extensions()?;
        let rc = extensions.required_capabilities()?;
        if pt.iter().all(|p| rc.proposal_types.contains(p)) {
            return Ok(Caniuse::Yes);
        }

        // otherwise all the members could support it whereas it's not required
        // note that this is expensive so we're relying upon of the fact that most of the time the required capabilities will be set right
        let mut all_clients = true;
        for (_, members) in self.user_roster()? {
            if pt.iter().any(|p| {
                let mut at_least_one_client_supports = false;
                let all_clients_support = members.iter().all(|m| {
                    let supports = m.capabilities.proposals.contains(p);
                    at_least_one_client_supports |= supports;
                    supports
                });
                all_clients &= all_clients_support;

                // if not a single client supports it, we bail
                !at_least_one_client_supports
            }) {
                return Ok(Caniuse::No);
            }
        }

        if all_clients {
            Ok(Caniuse::Yes)
        } else {
            Ok(Caniuse::YesAtLeastOneClient)
        }
    }

    /// Returns true if all the clients in the group supports the extension
    fn caniuse_extensions(&self, et: &[ExtensionType]) -> MlsResult<Caniuse> {
        // if all are default
        if et.iter().all(|e| e.is_spec_default()) {
            return Ok(Caniuse::Yes);
        }
        // if it's in the required capabilities it means all the MLS client HAVE TO support it
        let extensions = self.extensions()?;
        let rc = extensions.required_capabilities()?;
        if et.iter().all(|e| rc.extension_types.contains(e)) {
            return Ok(Caniuse::Yes);
        }

        // otherwise all the members could support it whereas it's not required
        // note that this is expensive so we're relying upon of the fact that most of the time the required capabilities will be set right
        let mut all_clients = true;
        for (_, members) in self.user_roster()? {
            if et.iter().any(|e| {
                let mut at_least_one_client_supports = false;
                let all_clients_support = members.iter().all(|m| {
                    let supports = m.capabilities.extensions.contains(e);
                    at_least_one_client_supports |= supports;
                    supports
                });
                all_clients &= all_clients_support;

                // if not a single client supports it, we bail
                !at_least_one_client_supports
            }) {
                return Ok(Caniuse::No);
            }
        }

        if all_clients {
            Ok(Caniuse::Yes)
        } else {
            Ok(Caniuse::YesAtLeastOneClient)
        }
    }

    /// Returns true if all the clients in the group supports the credential type
    fn caniuse_credential(&self, ct: &[CredentialType]) -> MlsResult<Caniuse> {
        // if all are default
        if ct
            .iter()
            .all(|&c| mls_spec::defs::CredentialType::from(c).is_spec_default())
        {
            return Ok(Caniuse::Yes);
        }
        // if it's in the required capabilities it means all the MLS client HAVE TO support it
        let extensions = self.extensions()?;
        let rc = extensions.required_capabilities()?;
        if ct.iter().all(|&c| rc.credential_types.contains(&c.into())) {
            return Ok(Caniuse::Yes);
        }

        // otherwise all the members could support it whereas it's not required
        // note that this is expensive so we're relying upon of the fact that most of the time the required capabilities will be set right
        let mut all_clients = true;
        for (_, members) in self.user_roster()? {
            if ct.iter().any(|&c| {
                let mut at_least_one_client_supports = false;
                let all_clients_support = members.iter().all(|m| {
                    let supports = m.capabilities.credentials.contains(&c.into());
                    at_least_one_client_supports |= supports;
                    supports
                });
                all_clients &= all_clients_support;

                // if not a single client supports it, we bail
                !at_least_one_client_supports
            }) {
                return Ok(Caniuse::No);
            }
        }

        if all_clients {
            Ok(Caniuse::Yes)
        } else {
            Ok(Caniuse::YesAtLeastOneClient)
        }
    }

    /// Returns true if all the clients in the group supports the app component
    fn caniuse_app_component(&self, ci: &[ComponentId]) -> MlsResult<Caniuse> {
        // first look for the supported app components in the group
        let Some(app_components) = self.extract_component::<AppComponents>()? else {
            return Ok(Caniuse::Unsure);
        };

        if ci.iter().all(|c| app_components.0.component_ids.contains(c)) {
            return Ok(Caniuse::Yes);
        }

        let mut all_clients = true;
        for (_, members) in self.user_roster()? {
            if ci.iter().any(|c| {
                let mut at_least_one_client_supports = false;
                let all_clients_support = members.iter().all(|m| {
                    let Some(app_data) = m.extensions.app_data() else {
                        return false;
                    };
                    let Ok(Some(app_components)) = app_data.extract_component::<AppComponents>() else {
                        return false;
                    };
                    let supports = app_components.0.component_ids.contains(c);
                    at_least_one_client_supports |= supports;
                    supports
                });
                all_clients &= all_clients_support;

                // if not a single client supports it, we bail
                !at_least_one_client_supports
            }) {
                return Ok(Caniuse::No);
            }
        }

        if all_clients {
            Ok(Caniuse::Yes)
        } else {
            Ok(Caniuse::YesAtLeastOneClient)
        }
    }

    /// Returns true if all the clients in the group supports the safe AAD component
    fn caniuse_safe_aad_component(&self, ci: &[ComponentId]) -> MlsResult<Caniuse> {
        // first look for the supported safe aad components in the group
        let Some(safe_aad_components) = self.extract_component::<SafeAadComponent>()? else {
            return Ok(Caniuse::Unsure);
        };

        if ci.iter().all(|c| safe_aad_components.0.component_ids.contains(c)) {
            return Ok(Caniuse::Yes);
        }

        let mut all_clients = true;
        for (_, members) in self.user_roster()? {
            if ci.iter().any(|c| {
                let mut at_least_one_client_supports = false;
                let all_clients_support = members.iter().all(|m| {
                    let Some(app_data) = m.extensions.app_data() else {
                        return false;
                    };
                    let Ok(Some(safe_aad_components)) = app_data.extract_component::<SafeAadComponent>() else {
                        return false;
                    };
                    let supports = safe_aad_components.0.component_ids.contains(c);
                    at_least_one_client_supports |= supports;
                    supports
                });
                all_clients &= all_clients_support;

                // if not a single client supports it, we bail
                !at_least_one_client_supports
            }) {
                return Ok(Caniuse::No);
            }
        }

        if all_clients {
            Ok(Caniuse::Yes)
        } else {
            Ok(Caniuse::YesAtLeastOneClient)
        }
    }

    /// Returns true if all the clients in the group supports the wire format
    fn caniuse_wire_format(&self, wfs: &[mls_spec::defs::WireFormat]) -> MlsResult<Caniuse> {
        // if all are default
        if wfs.iter().all(|wf| wf.is_spec_default()) {
            return Ok(Caniuse::Yes);
        }
        // if it's in the required wire format extension it means all the MLS client HAVE TO support it
        let extensions = self.extensions()?;
        if let Some(rc) = extensions.required_wire_formats()
            && wfs.iter().all(|wf| rc.wire_formats.contains(wf))
        {
            return Ok(Caniuse::Yes);
        }

        // otherwise all the members could support it whereas it's not required
        // note that this is expensive so we're relying upon of the fact that most of the time the required wire format will be set right
        let mut all_clients = true;
        for (_, members) in self.user_roster()? {
            if wfs.iter().any(|wf| {
                let mut at_least_one_client_supports = false;
                let all_clients_support = members.iter().all(|m| {
                    let Some(rc) = m.extensions.supported_wire_formats() else {
                        return false;
                    };
                    let supports = rc.wire_formats.contains(wf);
                    at_least_one_client_supports |= supports;
                    supports
                });
                all_clients &= all_clients_support;

                // if not a single client supports it, we bail
                !at_least_one_client_supports
            }) {
                return Ok(Caniuse::No);
            }
        }

        if all_clients {
            Ok(Caniuse::Yes)
        } else {
            Ok(Caniuse::YesAtLeastOneClient)
        }
    }

    /// Returns true if all the clients in the group supports the MediaType
    fn caniuse_media_type(&self, mt: &[MediaType]) -> MlsResult<Caniuse> {
        // if it's in the required wire format extension it means all the MLS client HAVE TO support it
        let extensions = self.extensions()?;
        if let Some(rc) = extensions.media_types()
            && mt.iter().all(|m| rc.0.contains(m))
        {
            return Ok(Caniuse::Yes);
        }

        // otherwise all the members could support it whereas it's not required
        // note that this is expensive so we're relying upon of the fact that most of the time the required wire format will be set right
        let mut all_clients = true;
        for (_, members) in self.user_roster()? {
            if mt.iter().any(|m| {
                let mut at_least_one_client_supports = false;
                let all_clients_support = members.iter().all(|member| {
                    let Some(rc) = member.extensions.media_types() else {
                        return false;
                    };
                    let supports = rc.0.contains(m);
                    at_least_one_client_supports |= supports;
                    supports
                });
                all_clients &= all_clients_support;

                // if not a single client supports it, we bail
                !at_least_one_client_supports
            }) {
                return Ok(Caniuse::No);
            }
        }

        if all_clients {
            Ok(Caniuse::Yes)
        } else {
            Ok(Caniuse::YesAtLeastOneClient)
        }
    }

    /// Deals with cases where one tries to add an extension or component not part of the capabilities
    fn merge_update_proposal_request(
        &self,
        extensions: Option<&Extensions>,
        capabilities: Option<&Capabilities>,
    ) -> MlsResult<Option<Capabilities>> {
        if let Some(extensions) = extensions.filter(|it| !it.is_empty()) {
            let mut capabilities = match capabilities {
                Some(capabilities) => capabilities.clone(),
                None => self.own_leaf_node()?.capabilities()?,
            };
            for ext in extensions.iter().filter(|ext| !ext.ext_type().is_spec_default()) {
                if !capabilities.extensions.contains(&ext.ext_type()) {
                    capabilities.extensions.push(ext.ext_type());
                }
            }
            return Ok(Some(capabilities));
        }

        Ok(None)
    }

    fn currents_roles(&self) -> MlsResult<Vec<Role>> {
        let authorizer = self.authorizer()?;
        let epoch = self.epoch();
        Ok(authorizer.roles(*epoch)?.cloned().collect())
    }

    fn own_user_role_for_current_epoch(&self) -> MlsResult<UserRole> {
        Ok(UserRole::from_index(self.own_role_for_current_epoch()?.role_index))
    }

    fn own_role_for_current_epoch(&self) -> MlsResult<Role> {
        let authorizer = self.authorizer()?;
        let epoch = self.epoch();
        Ok(authorizer.own_role(*epoch)?.clone())
    }

    fn user_role_for_current_epoch(&self, user_id: &UserId) -> MlsResult<UserRole> {
        let authorizer = self.authorizer()?;
        let epoch = self.epoch();
        let role = authorizer.role_for_user(*epoch, &UserIdentifier::from(user_id.to_string()))?;
        Ok(UserRole::from_index(role.role_index))
    }
}

#[allow(private_bounds, async_fn_in_trait)]
pub trait MlsGroupPendingReInitTrait {
    async fn is_reinit_sender(&self) -> MlsResult<bool>;

    #[allow(refining_impl_trait)]
    async fn commit_reinit(self, key_packages: Vec<KeyPackage>) -> MlsResult<(impl MlsGroupTrait, CommitBundle)>;

    #[allow(refining_impl_trait)]
    async fn join_reinit(self, welcome: MlsMessage, ratchet_tree: PublicRatchetTree) -> MlsResult<impl MlsGroupTrait>;
}
