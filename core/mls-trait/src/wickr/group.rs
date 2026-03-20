use super::identity::{ProtonMeetClaimExtractor, ProtonMeetIdentityProvider};
use crate::{
    Authorizer, Initialized, KvExt, MlsError, MlsGroupState, MlsGroupTrait, MlsResult, PendingReInit, ProposalArg,
    ReceiverReInitOutput, SenderReInitOutput, Uninitialized,
    mimi_protocol_mls::{
        UserIdentifier,
        components::metadata::RoomMetadata,
        reexports::{
            mls_spec::{
                Serializable,
                drafts::mls_extensions::{content_advertisement::ApplicationFraming, safe_application::Component},
            },
            tls_codec,
        },
    },
    mimi_room_policy::{MimiPolicyError, authorizer::AuthorizerError},
    traits::group::MlsGroupPendingReInitTrait,
    types::{CommitBundle, CommitOutput, PreviousGroupState, ReceivedMessage, ReceivedMessages},
    wickr::StdMlsClientConfig,
};
use itertools::Itertools;
use meet_identifiers::{DeviceId, Epoch, GroupId, LeafIndex, RoomId, UserId};
use mls_rs::{
    ExtensionList,
    extension::built_in::ExternalSendersExt,
    framing::{Content, FramedContent, MlsMessagePayload, PublicMessage},
    group::{
        CommitEffect, ReinitClient,
        framing::Sender as WickrSender,
        proposal::{AppDataUpdateOperation, ProposalOrRef},
    },
    identity::CustomCredential,
};
use mls_rs_codec::MlsEncode;
use mls_rs_core::identity::SigningIdentity;
use mls_types::{
    AppDataDictionaryExt, CipherSuite, Credential, ExtensionListExt, Extensions, HashAlgorithm, KeyPackage, LeafNode,
    MediaType, Member, MlsMessage, Proposal, ProtocolVersion, PublicRatchetTree, Sender, get_component,
};
use proton_claims::reexports::CwtAny;
use std::collections::BTreeSet;

#[derive(Clone)]
pub struct MlsGroup<Kv: KvExt + Send + Sync + Clone, S: MlsGroupState = Initialized>(
    pub(crate) Box<mls_rs::Group<StdMlsClientConfig<Kv>>>,
    pub(crate) core::marker::PhantomData<S>,
);

impl<Kv: KvExt + Send + Sync + Clone> MlsGroup<Kv> {
    pub async fn write_to_storage(&mut self) -> MlsResult<usize> {
        Ok(Box::pin(self.0.write_to_storage()).await?)
    }

    async fn _decrypt_message(
        &mut self,
        message: MlsMessage,
    ) -> MlsResult<(
        ReceivedMessage,
        Option<ReceiverReInitOutput<MlsGroup<Kv, PendingReInit>>>,
    )> {
        if self.is_duplicate_commit(&message) || self.is_duplicate_proposal(&message) {
            return Ok((ReceivedMessage::Duplicate, None));
        }

        let commit_contained_proposals_by_ref = Self::commit_contains_proposals_by_ref(&message);
        let new_update_path_leaf_node = Self::commit_update_path_leaf_node(&message)?;

        let old_state = PreviousGroupState {
            roster: self.roster().collect(),
            app_data: self.application_data()?,
        };

        let process_message_result = if let Some(vt) = message.virtual_time() {
            self.0
                .process_incoming_message_with_time(message.into(), vt.into())
                .await
        } else {
            self.0.process_incoming_message(message.into()).await
        };

        let received_message = match process_message_result {
            Ok(m) => ReceivedMessage::compute(
                self,
                m,
                old_state,
                commit_contained_proposals_by_ref,
                new_update_path_leaf_node,
            )?,
            // in mls-rs the secret tree history is infinite for this error does indicate a duplicate
            Err(mls_rs::error::MlsError::KeyMissing(_)) => ReceivedMessage::Duplicate,
            Err(mls_rs::error::MlsError::CantProcessMessageFromSelf) => ReceivedMessage::SelfMessage,
            Err(mls_rs::error::MlsError::EpochNotFound) => ReceivedMessage::EpochMismatch,
            Err(mls_rs::error::MlsError::RcAeadError) => ReceivedMessage::Corrupted,
            Err(mls_rs::error::MlsError::CryptoProviderError(e))
                if e.to_string()
                    == format!(
                        "the provided length of the key 0 is shorter than the minimum length {}",
                        self.ciphersuite()?.kdf_extract_size()
                    ) =>
            {
                ReceivedMessage::Ignored
            }
            Err(e) => ReceivedMessage::Error(e.into()),
        };

        match &received_message {
            ReceivedMessage::ReInit { .. } => {
                let reinit = ReceiverReInitOutput {
                    group: MlsGroup(self.0.clone(), core::marker::PhantomData::<PendingReInit>),
                };
                Ok((received_message, Some(reinit)))
            }
            _ => Ok((received_message, None)),
        }
    }

    // TODO: contribute this in mls-rs by returning a dedicated error code
    // FIXME: this does not work for PrivateMessage
    fn is_duplicate_proposal(&self, message: &MlsMessage) -> bool {
        let mp = message.as_proposal();
        self.0.pending_proposals().any(|p| mp == Some(p))
    }

    // TODO: contribute this in mls-rs by returning a dedicated error code
    // FIXME: this does not work for PrivateMessage
    fn is_duplicate_commit(&self, message: &MlsMessage) -> bool {
        let ct = self.0.confirmation_tag().as_slice();
        message.confirmation_tag() == Some(ct)
    }

    /// Examine a commit message looking for proposal by reference which would mean we have an
    /// existing timer for commiting them
    fn commit_contains_proposals_by_ref(message: &MlsMessage) -> bool {
        match &message.as_inner().payload {
            MlsMessagePayload::Plain(PublicMessage {
                content:
                    FramedContent {
                        content: Content::Commit(commit),
                        ..
                    },
                ..
            }) => commit
                .proposals
                .iter()
                .any(|p| matches!(p, ProposalOrRef::Reference(_))),
            _ => false,
        }
    }

    fn commit_update_path_leaf_node(message: &MlsMessage) -> MlsResult<Option<LeafNode>> {
        Ok(match &message.as_inner().payload {
            MlsMessagePayload::Plain(PublicMessage {
                content:
                    FramedContent {
                        content: Content::Commit(commit),
                        ..
                    },
                ..
            }) => commit
                .as_ref()
                .path
                .as_ref()
                .map(|p| p.leaf_node.clone().try_into())
                .transpose()?,
            _ => None,
        })
    }

    pub(crate) fn get_component<C: Component + tls_codec::Deserialize>(&self) -> MlsResult<Option<C>> {
        if let Some(application_data) = self.application_data()? {
            Ok(get_component::<C>(&application_data)?)
        } else {
            Ok(None)
        }
    }

    pub fn delegate(&mut self) -> &mut mls_rs::Group<StdMlsClientConfig<Kv>> {
        &mut self.0
    }

    // In charge of generating a unique identifier to put in the AAD for correlating commits.
    // It's only used for logging purpose so it's fine if inaccurate and returns an empty array
    fn commit_id(&self, proposals: &[ProposalArg]) -> [u8; 32] {
        use sha2::digest::Digest as _;

        let group_id = self.0.group_id();
        let epoch = self.0.current_epoch();
        let pending_proposals = self
            .0
            .pending_proposals()
            .filter_map(|p| p.mls_encode_to_vec().ok())
            .map(|b| format!("{b:x?}"))
            .collect::<Vec<String>>()
            .join("");
        let proposals = proposals.iter().map(Self::proposal_arg_id).collect::<Vec<_>>().join("");
        let id = format!("commit-{group_id:x?}-{epoch}-{pending_proposals}-{proposals}");
        sha2::Sha256::digest(&id[..]).into()
    }

    // In charge of generating a unique identifier to put in the AAD for correlating proposals.
    // It's only used for logging purpose so it's fine if inaccurate and returns an empty array
    fn proposal_id(&self, proposal: &ProposalArg) -> [u8; 32] {
        use sha2::digest::Digest as _;

        let group_id = self.0.group_id();
        let epoch = self.0.current_epoch();
        let proposal = Self::proposal_arg_id(proposal);
        let id = format!("proposal-{group_id:x?}-{epoch}-{proposal}");
        sha2::Sha256::digest(&id[..]).into()
    }

    fn proposal_arg_id(proposal: &ProposalArg) -> String {
        match proposal {
            ProposalArg::Remove(i) => format!("remove-{i}"),
            ProposalArg::Add(kp) => format!("add-{:x?}", kp.mls_encode_to_vec().unwrap_or_default()),
            ProposalArg::PskExternal { id } => format!("psk-external-{:x?}", &id.0),
            ProposalArg::Update {
                credential,
                extensions,
                capabilities,
            } => {
                use crate::mimi_protocol_mls::reexports::tls_codec::Serialize as _;
                let credential = credential
                    .as_ref()
                    .map(|c| c.to_cbor_bytes().unwrap_or_default())
                    .unwrap_or_default();
                let extensions = extensions
                    .as_ref()
                    .map(|e| e.tls_serialize_detached().unwrap_or_default())
                    .unwrap_or_default();
                let capabilities = capabilities
                    .as_ref()
                    .map(|e| e.tls_serialize_detached().unwrap_or_default())
                    .unwrap_or_default();
                format!("update-{credential:x?}-{extensions:x?}-{capabilities:x?}",)
            }
            ProposalArg::UpdateComponent { id, data } => format!("update-component-{id}-{data:x?}"),
            ProposalArg::RemoveComponent(i) => format!("remove-component-{i}"),
            ProposalArg::ReInit {
                new_ciphersuite,
                new_protocol_version,
            } => format!("reinit-{new_ciphersuite:?}-{new_protocol_version:?}"),
            &ProposalArg::GroupContextExtension(_) => "group-context-extension".into(),
        }
    }
}

impl<Kv: KvExt + Send + Sync + Clone> MlsGroup<Kv, Uninitialized> {
    pub async fn store(mut self) -> MlsResult<MlsGroup<Kv, Initialized>> {
        let _ = self.0.write_to_storage().await?;
        Ok(MlsGroup(self.0, core::marker::PhantomData))
    }

    pub fn epoch(&self) -> Epoch {
        self.0.current_epoch().into()
    }
}

impl<Kv: KvExt + Send + Sync + Clone> MlsGroupTrait for MlsGroup<Kv> {
    fn id(&self) -> MlsResult<GroupId> {
        Ok(GroupId::try_from(self.0.group_id())?)
    }

    fn room_id(&self) -> MlsResult<RoomId> {
        let room_metadata = self.get_metadata()?;
        Ok(room_metadata.room_uri.uri.parse()?)
    }

    async fn encrypt_messages<M>(
        &mut self,
        user_messages: impl IntoIterator<Item = (MediaType, M)>,
    ) -> MlsResult<Vec<MlsMessage>>
    where
        M: Into<Vec<u8>>,
    {
        let user_messages = user_messages.into_iter();
        let (lb, ub) = user_messages.size_hint();
        let size = ub.unwrap_or(lb);

        let mut mls_messages = Vec::with_capacity(size);

        for (mt, m) in user_messages {
            let af = ApplicationFraming {
                media_type: mt.into(),
                inner_application_content: m.into(),
            };
            let m = self.0.encrypt_application_message(&af.to_tls_bytes()?, vec![]).await?;
            mls_messages.push(m.into());
        }

        self.write_to_storage().await?;

        Ok(mls_messages)
    }

    async fn encrypt_message(&mut self, media_type: MediaType, user_message: &[u8]) -> MlsResult<MlsMessage> {
        let af = ApplicationFraming {
            media_type: media_type.into(),
            inner_application_content: user_message.to_vec(),
        };
        let encrypted = self.0.encrypt_application_message(&af.to_tls_bytes()?, vec![]).await?;
        self.write_to_storage().await?;
        Ok(encrypted.into())
    }

    fn ciphersuite(&self) -> MlsResult<CipherSuite> {
        let cs = self.0.cipher_suite().raw_value();
        Ok(CipherSuite::try_from(cs)?)
    }

    #[allow(refining_impl_trait)]
    async fn decrypt_messages(
        &mut self,
        messages: impl IntoIterator<Item: Into<MlsMessage>>,
    ) -> MlsResult<(
        ReceivedMessages,
        Option<ReceiverReInitOutput<MlsGroup<Kv, PendingReInit>>>,
    )> {
        let messages = messages.into_iter();
        let (lb, ub) = messages.size_hint();
        let size = ub.unwrap_or(lb);

        let mut decrypted_messages = Vec::with_capacity(size);

        let mut reinit = None;
        let mut persist_group = false;
        #[cfg(debug_assertions)]
        let pre_snapshot = self.0.snapshot().expect("failed to snapshot group");

        for m in messages {
            let (msg, mut reinit_output) = self._decrypt_message(m.into()).await?;

            // in case of an error, duplicate, general failure to decrypt, no need to persist anything
            persist_group |= matches!(
                msg,
                ReceivedMessage::ApplicationMessage { .. }
                    | ReceivedMessage::Proposal
                    | ReceivedMessage::Commit { .. }
                    | ReceivedMessage::ReInit { .. }
                    | ReceivedMessage::Corrupted
            );

            decrypted_messages.push(msg);
            if let Some(r) = reinit_output.take() {
                reinit.replace(r);
            }
        }

        if persist_group {
            #[cfg(debug_assertions)]
            if pre_snapshot == self.0.snapshot().expect("failed to snapshot group") {
                tracing::debug!("[PERF] Unchanged MLS group, persisting the group is not required")
            }
            self.write_to_storage().await?;
        } else {
            #[cfg(debug_assertions)]
            assert_eq!(
                pre_snapshot,
                self.0.snapshot().expect("failed to snapshot group"),
                "[BUG] MLS group state changed and not persisted"
            );
        }

        let decrypted_messages = decrypted_messages.into();
        Ok((decrypted_messages, reinit))
    }

    #[allow(refining_impl_trait)]
    async fn decrypt_message(
        &mut self,
        message: impl Into<MlsMessage>,
    ) -> MlsResult<(
        ReceivedMessage,
        Option<ReceiverReInitOutput<MlsGroup<Kv, PendingReInit>>>,
    )> {
        #[cfg(debug_assertions)]
        let pre_snapshot = self.0.snapshot().expect("failed to snapshot group");

        let (decrypted, reinit) = self._decrypt_message(message.into()).await?;
        match decrypted {
            ReceivedMessage::ApplicationMessage { .. }
            | ReceivedMessage::Commit { .. }
            | ReceivedMessage::ReInit { .. }
            | ReceivedMessage::Proposal => {
                #[cfg(debug_assertions)]
                if pre_snapshot == self.0.snapshot().expect("failed to snapshot group") {
                    tracing::debug!(
                        "[PERF] Unchanged MLS group for {decrypted:?}, persisting the group is not required"
                    )
                }
                tracing::trace!("Message decrypted");
                self.write_to_storage().await?;
            }
            ReceivedMessage::Corrupted => {
                // the state of the group has been changed even though the message was invalid, this is bad.
                // it has to be fixed in mls-rs, meanwhile any attempt to fix it here could make things worse.
                // TODO: so we will just persist the new state (w/ increased generation) for now
                // this could be exploited by a malicious insider to continuously force the receivers
                // to do useless KDFs, draining their batteries
                tracing::warn!("Decrypted a corrupted message");
                self.write_to_storage().await?;
            }
            ReceivedMessage::SelfMessage
            | ReceivedMessage::Error(_)
            | ReceivedMessage::Ignored
            | ReceivedMessage::Duplicate
            | ReceivedMessage::EpochMismatch => {
                #[cfg(debug_assertions)]
                assert_eq!(
                    pre_snapshot,
                    self.0.snapshot().expect("failed to snapshot group"),
                    "[BUG] MLS group state changed and not persisted"
                );

                // no need to persist anything in these cases
                tracing::trace!("Decrypted a message we can ignore {:?}", decrypted);
            }
        };
        Ok((decrypted, reinit))
    }

    //noinspection ALL
    async fn new_proposals(&mut self, proposals: impl IntoIterator<Item = ProposalArg>) -> MlsResult<Vec<MlsMessage>> {
        let proposals = proposals.into_iter();

        let (lb, ub) = proposals.size_hint();
        let size = ub.unwrap_or(lb);

        let mut mls_messages = Vec::with_capacity(size);

        for p in proposals {
            let m = match p {
                ProposalArg::Add(key_package) => self.0.propose_add((*key_package).into(), vec![]).await?,
                ProposalArg::Remove(to_remove) => self.0.propose_remove(*to_remove, vec![]).await?,
                ProposalArg::PskExternal { .. } => {
                    return Err(MlsError::ImplementationError(
                        "By-ref PSK proposal path is out of scope; use new_commit with ProposalArg::PskExternal",
                    ));
                }
                ProposalArg::Update {
                    credential,
                    extensions,
                    mut capabilities,
                } => {
                    let si = if let Some(sd_kbt) = credential.as_ref() {
                        let pk = self.0.current_member_signing_identity()?.signature_key.clone();
                        let sd_kbt = sd_kbt.to_cbor_bytes()?;
                        let credential = mls_rs_core::identity::Credential::Custom(CustomCredential {
                            credential_type: mls_spec::defs::CredentialType::SD_CWT_CREDENTIAL.into(),
                            data: sd_kbt,
                        });
                        Some(SigningIdentity::new(credential, pk))
                    } else {
                        None
                    };

                    capabilities = self.merge_update_proposal_request(extensions.as_ref(), capabilities.as_ref())?;

                    let extensions = extensions.map(TryFrom::try_from).transpose()?;

                    let capabilities = capabilities.map(Into::into);

                    self.0
                        .raw_propose_update(None, si, extensions, capabilities, vec![])
                        .await?
                }
                ProposalArg::UpdateComponent { id, data } => {
                    self.0
                        .propose_app_data_update(id, AppDataUpdateOperation::Update(data), vec![])
                        .await?
                }
                ProposalArg::RemoveComponent(id) => {
                    self.0
                        .propose_app_data_update(id, AppDataUpdateOperation::Remove, vec![])
                        .await?
                }
                ProposalArg::ReInit {
                    new_ciphersuite,
                    new_protocol_version,
                } => {
                    let (new_group_id, new_protocol_version, new_ciphersuite, new_extensions) =
                        self.reinit_proposal(new_ciphersuite, new_protocol_version)?;
                    self.0
                        .propose_reinit(
                            new_group_id,
                            new_protocol_version.into(),
                            new_ciphersuite.into(),
                            new_extensions.try_into()?,
                            vec![],
                        )
                        .await?
                }
                ProposalArg::GroupContextExtension(new_extensions) => {
                    self.0
                        .propose_group_context_extensions(new_extensions.try_into()?, vec![])
                        .await?
                }
            }
            .into();
            mls_messages.push(m);
        }

        self.write_to_storage().await?;

        Ok(mls_messages)
    }

    async fn new_commit(
        &mut self,
        proposals: impl IntoIterator<Item = ProposalArg>,
    ) -> MlsResult<(CommitBundle, bool)> {
        if self.has_pending_commit() {
            self.clear_pending_commit();
        }

        let mut proposals = proposals.into_iter().collect::<Vec<ProposalArg>>();

        // we have to preemptively extract this here because 'commit_builder' takes a &mut self
        let mut reinit_args = proposals
            .iter()
            .find_map(|p| match p {
                ProposalArg::ReInit {
                    new_ciphersuite,
                    new_protocol_version,
                } => Some(self.reinit_proposal(*new_ciphersuite, *new_protocol_version)),
                _ => None,
            })
            .transpose()?;
        let current_member_signing_identity = self.0.current_member_signing_identity()?.clone();

        // Same reason ("we have to preemptively extract this here because 'commit_builder' takes a &mut self")
        for p in &mut proposals {
            if let ProposalArg::Update {
                extensions,
                capabilities,
                ..
            } = p
                && let Some(updated_capabilities) =
                    self.merge_update_proposal_request(extensions.as_ref(), capabilities.as_ref())?
            {
                capabilities.replace(updated_capabilities);
            }
        }

        let mut builder = self.0.commit_builder();

        for p in proposals {
            match p {
                ProposalArg::Add(key_package) => {
                    builder = builder.add_member((*key_package).into())?;
                }
                ProposalArg::Remove(to_remove) => {
                    builder = builder.remove_member(*to_remove)?;
                }
                ProposalArg::PskExternal { id } => {
                    builder = builder.add_external_psk(id.into())?;
                }
                ProposalArg::Update {
                    credential,
                    extensions,
                    capabilities,
                } => {
                    if let Some(sd_kbt) = credential.as_ref() {
                        let pk = current_member_signing_identity.signature_key.clone();
                        let sd_kbt = sd_kbt.to_cbor_bytes()?;
                        let credential = mls_rs_core::identity::Credential::Custom(CustomCredential {
                            credential_type: mls_spec::defs::CredentialType::SD_CWT_CREDENTIAL.into(),
                            data: sd_kbt,
                        });
                        let si = SigningIdentity::new(credential, pk);
                        builder = builder.set_new_signing_identity_same_signature_key(si);
                    }

                    if let Some(extensions) = extensions {
                        builder = builder.set_leaf_node_extensions(extensions.try_into()?);
                    }
                    if let Some(capabilities) = capabilities {
                        builder = builder.set_leaf_node_capabilities(capabilities.into());
                    }
                }
                ProposalArg::UpdateComponent { id, data } => {
                    builder = builder.application_data_update(id, AppDataUpdateOperation::Update(data))?;
                }
                ProposalArg::RemoveComponent(id) => {
                    builder = builder.application_data_update(id, AppDataUpdateOperation::Remove)?;
                }
                ProposalArg::ReInit { .. } => {
                    let (new_group_id, new_protocol_version, new_ciphersuite, new_extensions) = reinit_args
                        .take()
                        .ok_or(MlsError::ImplementationError("Wrong usage of ReInit"))?;
                    builder = builder.reinit(
                        new_group_id,
                        new_protocol_version.into(),
                        new_ciphersuite.into(),
                        new_extensions.try_into()?,
                    )?
                }
                ProposalArg::GroupContextExtension(new_extensions) => {
                    builder = builder.set_group_context_ext(new_extensions.try_into()?)?;
                }
            }
        }

        let commit_output = builder.build().await;
        // if we could not authorize the proposals, then we should remove them from the proposal cache
        if let Err(mls_rs::error::MlsError::MlsRulesError(_)) = &commit_output {
            self.0.clear_proposal_cache();
        }
        let bundle: CommitBundle = commit_output?.try_into()?;

        let contains_proposals_by_ref = Self::commit_contains_proposals_by_ref(&bundle.commit);

        self.write_to_storage().await?;

        Ok((bundle, contains_proposals_by_ref))
    }

    #[allow(refining_impl_trait)]
    async fn merge_pending_commit(
        &mut self,
    ) -> MlsResult<(CommitOutput, Option<SenderReInitOutput<MlsGroup<Kv, PendingReInit>>>)> {
        let Some(pending_commit) = self.0.pending_commit()? else {
            return Err(MlsError::ImplementationError("Tried to merge an absent pending commit"));
        };

        let updated_leaf_node = pending_commit
            .new_leaf_node
            .clone()
            .map(TryFrom::try_from)
            .transpose()?;

        let mut old_state = PreviousGroupState {
            roster: self.roster().collect(),
            app_data: self.application_data()?,
        };
        let description = self.0.apply_pending_commit().await?;
        self.write_to_storage().await?;

        let reinit = match &description.effect {
            CommitEffect::ReInit(proposal) => Some(SenderReInitOutput {
                group: MlsGroup(self.0.clone(), core::marker::PhantomData::<PendingReInit>),
                user_ids: self.all_user_ids()?,
                ciphersuite: proposal.proposal.new_cipher_suite().try_into()?,
            }),
            _ => None,
        };

        let output = CommitOutput::compute(self, &mut old_state, description, updated_leaf_node)?;
        Ok((output, reinit))
    }

    fn clear_pending_commit(&mut self) {
        self.0.clear_pending_commit()
    }

    fn find_member(&self, index: LeafIndex) -> MlsResult<Member> {
        Ok(self
            .0
            .member_at_index(*index)
            .ok_or(MlsError::MemberNotFound(index))?
            .try_into()?)
    }

    fn find_sender(&self, sender: &Sender) -> MlsResult<Option<Credential>> {
        Ok(match sender {
            Sender::Member(leaf_index) => Some(self.find_member((*leaf_index).try_into()?)?.into_credential()),
            Sender::External(external_sender_index) => {
                let Some(external_senders) = self.0.context().extensions().get_as::<ExternalSendersExt>()? else {
                    return Ok(None);
                };
                let Some(si) = external_senders.allowed_senders.get(*external_sender_index as usize) else {
                    return Ok(None);
                };
                Some(si.credential.clone().try_into()?)
            }
            Sender::NewMemberCommit | Sender::NewMemberProposal => None,
        })
    }

    fn member_index(&self, cred: &mut Credential) -> MlsResult<LeafIndex> {
        for member in self.0.roster().members_iter() {
            let c = Credential::try_from(member.signing_identity.credential)?;
            if cred == &c {
                let index = LeafIndex::try_from(member.index)?;
                return Ok(index);
            }
        }
        Err(MlsError::MemberIndexNotFound(cred.user_id().ok()))
    }

    fn own_leaf_index(&self) -> MlsResult<LeafIndex> {
        Ok(self.0.current_member_index().try_into()?)
    }

    fn own_leaf_node(&self) -> MlsResult<LeafNode> {
        Ok(self.0.current_user_leaf_node()?.clone().try_into()?)
    }

    fn epoch(&self) -> Epoch {
        self.0.current_epoch().into()
    }

    fn roster(&self) -> impl Iterator<Item = Member> {
        self.0
            .roster()
            .members_iter()
            // we could fail here but the odd this occurs are rare and given how big this can be we must avoid collecting
            .filter_map(|m| m.try_into().ok())
    }

    fn all_device_ids(&self) -> impl Iterator<Item = DeviceId> {
        self.roster().filter_map(|mut m| m.device_id().ok())
    }

    fn users_about_to_be_removed(&self, proposals: &[ProposalArg]) -> MlsResult<Vec<UserId>> {
        let mut leaves_to_remove = proposals
            .iter()
            .filter_map(|p| match p {
                ProposalArg::Remove(index) => Some(*std::ops::Deref::deref(index)),
                _ => None,
            })
            .collect::<BTreeSet<u32>>();

        // do not forget about pending proposals !
        self.pending_proposals()?.iter().for_each(|p| {
            if let Proposal::Remove(p) = p {
                leaves_to_remove.insert(p.to_remove());
            }
        });

        Ok(self
            .0
            .as_ref()
            .roster()
            .members_iter()
            .filter_map(|m| Member::try_from(m).ok())
            .filter_map(|mut m| m.user_id().ok().map(|id| (m, id)))
            .chunk_by(|(_, uid)| uid.clone())
            .into_iter()
            .filter_map(|(uid, mut group)| {
                group
                    .all(|(m, _)| leaves_to_remove.contains(&m.leaf_index))
                    .then_some(uid)
            })
            .collect())
    }

    fn roster_leaf_indexes(&self) -> MlsResult<Vec<LeafIndex>> {
        self.0
            .roster()
            .members_iter()
            .map(|m| m.index.try_into().map_err(Into::into))
            .collect::<MlsResult<Vec<_>>>()
    }

    fn pending_proposals(&self) -> MlsResult<Vec<mls_types::Proposal>> {
        Ok(self
            .0
            .pending_proposals()
            .cloned()
            .map(TryInto::try_into)
            .collect::<Result<_, _>>()?)
    }

    fn clear_pending_proposals(&mut self) {
        self.0.clear_proposal_cache();
    }

    fn hash_algorithm(&self) -> MlsResult<HashAlgorithm> {
        Ok(self.ciphersuite()?.hash_alg())
    }

    async fn bare_group_info_no_ext_commit(&self) -> MlsResult<MlsMessage> {
        Ok(self.0.group_info_message(false).await?.into())
    }

    async fn group_info_for_ext_commit(&self) -> MlsResult<MlsMessage> {
        Ok(self.0.group_info_message_allowing_ext_commit(false).await?.into())
    }

    fn ratchet_tree(&self) -> mls_rs::group::ExportedTree<'static> {
        self.0.export_tree().into_owned()
    }

    fn extensions(&self) -> MlsResult<Extensions> {
        Ok(self.0.context().extensions().clone().try_into()?)
    }

    fn application_data(&self) -> MlsResult<Option<mls_rs::group::ApplicationDataDictionary>> {
        Ok(self.0.context().extensions.application_data()?)
    }

    fn update_metadata(&self, new_meta: RoomMetadata) -> MlsResult<ProposalArg> {
        let old = self.get_metadata()?;
        if old.room_uri != new_meta.room_uri {
            return Err(MlsError::ImplementationError("Cannot edit the room_uri"));
        }
        ProposalArg::update_component(&new_meta)
    }

    fn authorizer(&self) -> MlsResult<Authorizer> {
        let mut authorizer = Authorizer::default();

        let app_data = self.application_data_spec()?.ok_or_else(|| {
            MlsError::MimiPolicyError(MimiPolicyError::AuthorizerError(
                AuthorizerError::MissingApplicationData,
            ))
        })?;
        let signing_identity = self.0.current_member_signing_identity()?;
        let current_identity = ProtonMeetIdentityProvider::identity_from_signing_identity(signing_identity)?;
        let claim_extractor = ProtonMeetClaimExtractor::new(signing_identity.credential.clone())?;

        authorizer.add_application_data(*self.epoch(), &app_data, &current_identity, &claim_extractor)?;

        Ok(authorizer)
    }

    fn member_identity(&self, credential: &Credential) -> MlsResult<UserIdentifier> {
        ProtonMeetIdentityProvider::identity_from_credential(&mut credential.clone(), &ExtensionList::default())
    }

    fn has_pending_commit(&self) -> bool {
        self.0.has_pending_commit()
    }

    fn protocol_version(&self) -> MlsResult<ProtocolVersion> {
        Ok(self.0.protocol_version().try_into()?)
    }

    async fn export_secret(&self, label: &'static str, context: &[u8], len: usize) -> MlsResult<mls_types::Secret> {
        Ok(self
            .0
            .export_secret(label.as_bytes(), context, len)
            .await?
            .to_vec()
            .into())
    }

    fn epoch_authenticator(&self) -> MlsResult<mls_types::Secret> {
        Ok(self.0.epoch_authenticator()?.to_vec().into())
    }
}

impl<Kv: KvExt + Send + Sync + Clone> MlsGroupPendingReInitTrait for MlsGroup<Kv, PendingReInit> {
    async fn is_reinit_sender(&self) -> MlsResult<bool> {
        // will help to determine whether we have to commit or join the group
        let reinit_sender = *self.0.pending_reinit_sender().ok_or(MlsError::ImplementationError(
            "Trying to reinit the group without an associated ReInit proposal received",
        ))?;
        let own_leaf_index = self.0.current_member_index();

        Ok(match reinit_sender {
            WickrSender::NewMemberProposal | WickrSender::NewMemberCommit => {
                return Err(MlsError::ImplementationError("Invalid sender for ReInit"));
            }
            WickrSender::Member(index) if index == own_leaf_index => true,
            _ => false,
        })
    }

    #[allow(refining_impl_trait)]
    async fn commit_reinit(
        self,
        key_packages: Vec<KeyPackage>,
    ) -> MlsResult<(MlsGroup<Kv, Initialized>, CommitBundle)> {
        let app_data_dictionary = self.0.context().extensions().application_data()?.unwrap_or_default();

        let reinit_client: ReinitClient<StdMlsClientConfig<Kv>> = self.0.get_reinit_client(None, None)?;
        let kps = key_packages.into_iter().map(Into::into).collect();

        let mut new_leaf_node_extensions = ExtensionList::default();
        new_leaf_node_extensions.set(app_data_dictionary.to_mls_rs_extension()?);

        let (group, commit_output) = reinit_client.commit(kps, new_leaf_node_extensions, None).await?;
        let group = MlsGroup(Box::new(group), core::marker::PhantomData::<Initialized>);
        let bundle: CommitBundle = commit_output.try_into()?;
        Ok((group, bundle))
    }

    #[allow(refining_impl_trait)]
    async fn join_reinit(
        self,
        welcome: MlsMessage,
        ratchet_tree: PublicRatchetTree,
    ) -> MlsResult<MlsGroup<Kv, Initialized>> {
        let reinit_client: ReinitClient<StdMlsClientConfig<Kv>> = self.0.get_reinit_client(None, None)?;
        let (group, _new_member_info) = reinit_client
            .join(&welcome.into(), Some(ratchet_tree.into()), None)
            .await?;
        let group = MlsGroup(Box::new(group), core::marker::PhantomData::<Initialized>);
        Ok(group)
    }
}

impl<Kv: KvExt + Send + Sync + Clone> std::fmt::Debug for MlsGroup<Kv, Uninitialized> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlsGroup uninitialized")
    }
}

impl<Kv: KvExt + Send + Sync + Clone> std::fmt::Debug for MlsGroup<Kv, PendingReInit> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlsGroup pending ReInit")
    }
}
