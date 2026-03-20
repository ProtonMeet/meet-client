use super::{StdMlsClientConfig, authorization::role_proposal_for_external_join, identity::ProtonMeetClaimExtractor};
use crate::mimi_protocol_mls::{UserIdentifier, reexports::mls_spec};
use crate::mimi_room_policy::{MimiPolicyError, authorizer::AuthorizerError};
use crate::{
    CommitBundle, Initialized, KvExt, MlsClientConfig, MlsClientState, MlsClientTrait, MlsError, MlsGroup,
    MlsGroupEntity, MlsIdentityEntity, MlsKeyPackageEntity, MlsResult, SignaturePK, Uninitialized,
    traits::config::MlsGroupConfig,
    types::ReceivedNewMemberMessage,
    wickr::{error::WickrProviderError, identity::ProtonMeetIdentityProvider, kv::IdentityKv},
};
use identity::{
    Disclosure, PresentationContext, ProtonMeetIdentity, SdCwt, VerifiedSdCwt, new_identity_presentation, verify_sd_cwt,
};
use meet_identifiers::{GroupId, Identifier, UserId};
use mls_rs::{
    CipherSuiteProvider, EncryptContext, SignContent,
    client_config::ClientConfig as _,
    group::{
        ExportedTree,
        external_commit::ExternalCommitBuilder,
        proposal::{AppDataUpdateOperation, AppDataUpdateProposal},
    },
    identity::CustomCredential,
    mls_rs_codec::MlsEncode,
    time::MlsTime,
};
use mls_rs_codec::MlsDecode;
use mls_rs_core::{
    crypto::CryptoProvider,
    crypto::HpkeContextR,
    error::IntoAnyError,
    identity::{Credential, SigningIdentity},
};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use mls_types::{
    CipherSuite, CredentialType, ExternalPsk, ExternalPskId, GroupInfo, GroupInfoRef, HpkeKeyPair, KeyPackage,
    KeyPackageRef, MlsMessage, PublicRatchetTree, Signature, SignatureAlgorithm, SignaturePublicKey,
};
use mls_types::{ExtensionListExt, GroupInfoExt};
use proton_claims::{
    UserAsserted,
    reexports::{CwtAny, cose_key_set::CoseKeySet},
};
use std::{
    collections::HashSet,
    fmt::Debug,
    hash::{Hash, Hasher},
};

#[inline]
fn time_to_mlsrs_time(time: u64) -> MlsTime {
    MlsTime::from_duration_since_epoch(std::time::Duration::from_secs(time))
}

#[derive(Debug)]
pub struct MlsClient<Kv, S: MlsClientState = Initialized>
where
    Kv: KvExt + Send + Sync,
{
    pub delegate: Option<mls_rs::Client<StdMlsClientConfig<Kv>>>,
    pub cs: CipherSuite,
    pub ct: CredentialType,
    pub signature_pk: mls_rs_core::crypto::SignaturePublicKey,
    pub signature_sk: mls_rs_core::crypto::SignatureSecretKey,
    pub config: Box<MlsClientConfig>,
    _state: core::marker::PhantomData<S>,
}

impl<Kv: KvExt + Send + Sync + Clone> MlsClient<Kv, Uninitialized> {
    pub async fn new(kv: Kv, config: MlsClientConfig) -> MlsResult<(Self, mls_types::SignaturePublicKey)> {
        let cs = config.ciphersuite;
        let (signature_sk, signature_pk) = Self::new_signature_keypair(cs).await?;
        let entity = MlsIdentityEntity::new((&signature_pk).into(), cs, signature_sk.as_bytes().to_vec().into());
        IdentityKv(kv).insert(&entity).await?;

        let client = Self {
            delegate: None,
            cs,
            ct: CredentialType::SdCwtDraft04,
            signature_pk: signature_pk.clone(),
            signature_sk,
            config: Box::new(config),
            _state: Default::default(),
        };
        Ok((client, signature_pk.into()))
    }

    /// Reverts [`Self::new`]
    pub async fn rollback(kv: Kv, signature_public_key: SignaturePublicKey) -> MlsResult<()> {
        let id = crate::kv::SignaturePK::from(signature_public_key);
        IdentityKv(kv).remove::<MlsIdentityEntity>(&id).await?;
        Ok(())
    }

    async fn new_signature_keypair(
        cs: CipherSuite,
    ) -> MlsResult<(mls_rs::crypto::SignatureSecretKey, mls_rs::crypto::SignaturePublicKey)> {
        let crypto_provider = RustCryptoProvider::with_enabled_cipher_suites(vec![cs.into()]);
        let cs_provider = crypto_provider
            .cipher_suite_provider(cs.into())
            .ok_or(MlsError::ImplementationError("Ciphersuite not supported"))?;

        // Generate a signature key pair
        Ok(cs_provider
            .signature_key_generate()
            .await
            .map_err(WickrProviderError::from)?)
    }

    /// Will set the sd_cwt of the client and make it ready for use
    pub fn initialize(
        self,
        kv: Kv,
        sd_cwt: SdCwt,
        auth_cks: &CoseKeySet,
        server_cks: &CoseKeySet,
    ) -> MlsResult<MlsClient<Kv, Initialized>> {
        let signer = self.signature_sk.as_bytes().to_vec();
        let alg = self.signature_algorithm()?;
        let sd_cwt_bytes = sd_cwt.to_cbor_bytes()?;
        let sd_cwt_verified = verify_sd_cwt(&sd_cwt_bytes, signer, alg, auth_cks)?.as_ref().clone();

        let cfg = StdMlsClientConfig::new(self.cs, auth_cks, server_cks, *self.config.clone(), kv, sd_cwt_verified);
        let client = Self::new_mls_rs_client(cfg, &self.config, self.cs, self.signature_sk.clone());

        Ok(MlsClient {
            delegate: Some(client),
            cs: self.cs,
            ct: self.ct,
            signature_pk: self.signature_pk,
            signature_sk: self.signature_sk,
            config: self.config,
            _state: Default::default(),
        })
    }

    /// tries to restore a client that is stored in the DB. Will return an error if the client could not be found in DB
    pub async fn restore(
        kv: Kv,
        mut config: MlsClientConfig,
        signature_pk: SignaturePK,
        auth_cks: &CoseKeySet,
        server_cks: &CoseKeySet,
        sd_cwt: SdCwt,
    ) -> MlsResult<MlsClient<Kv, Initialized>> {
        let identity = IdentityKv(kv.clone())
            .restore(signature_pk)
            .await?
            .ok_or(MlsError::ImplementationError(
                "Trying to restore a MLS identity not persisted",
            ))?;
        let cs = identity.cs;

        config.ciphersuite = cs;

        let (signature_sk, signature_pk) = Self::restore_signature_keypair(&identity)?;
        let uninitialized_client = Self {
            delegate: None,
            cs: config.ciphersuite,
            ct: CredentialType::SdCwtDraft04,
            signature_pk,
            signature_sk,
            config: Box::new(config),
            _state: Default::default(),
        };
        uninitialized_client.initialize(kv.clone(), sd_cwt, auth_cks, server_cks)
    }

    fn restore_signature_keypair(
        identity: &MlsIdentityEntity,
    ) -> MlsResult<(
        mls_rs_core::crypto::SignatureSecretKey,
        mls_rs_core::crypto::SignaturePublicKey,
    )> {
        let (sk, pk) = match identity.cs.signature_alg() {
            SignatureAlgorithm::Ed25519 => {
                let sk = ed25519_dalek::SigningKey::from_keypair_bytes(identity.signature_sk.as_bytes().try_into()?)?;
                let pk = sk.verifying_key();
                (sk.to_keypair_bytes().to_vec(), pk.as_bytes().to_vec())
            }
            SignatureAlgorithm::P256 => {
                let sk = p256::ecdsa::SigningKey::from_bytes(identity.signature_sk.as_bytes().into())?;
                let pk = *sk.verifying_key();
                (identity.signature_sk.as_bytes().to_vec(), pk.to_sec1_bytes().to_vec())
            }
            SignatureAlgorithm::P384 => {
                let sk = p384::ecdsa::SigningKey::from_bytes(identity.signature_sk.as_bytes().into())?;
                let pk = *sk.verifying_key();
                (identity.signature_sk.as_bytes().to_vec(), pk.to_sec1_bytes().to_vec())
            }
            SignatureAlgorithm::Ed448 | SignatureAlgorithm::P521 => unimplemented!(),
        };
        let sk = mls_rs_core::crypto::SignatureSecretKey::from(sk);
        let pk = mls_rs_core::crypto::SignaturePublicKey::from(pk);

        Ok((sk, pk))
    }
}

impl<Kv: KvExt + Send + Sync + Clone + Debug> MlsClient<Kv, Initialized> {
    pub fn delegate(&self) -> MlsResult<&mls_rs::Client<StdMlsClientConfig<Kv>>> {
        self.delegate
            .as_ref()
            .ok_or_else(|| MlsError::ImplementationError("MlsClient failed its delegate bookkeeping"))
    }

    pub fn delegate_mut(&mut self) -> MlsResult<&mut mls_rs::Client<StdMlsClientConfig<Kv>>> {
        self.delegate
            .as_mut()
            .ok_or_else(|| MlsError::ImplementationError("MlsClient failed its delegate bookkeeping"))
    }

    pub fn new_signing_identity(
        &self,
        disclosure: Disclosure,
        ctx: &PresentationContext,
    ) -> MlsResult<SigningIdentity> {
        let sd_kbt = self.new_identity_presentation(disclosure, None, ctx)?;
        let credential = Credential::Custom(CustomCredential {
            credential_type: mls_spec::defs::CredentialType::SD_CWT_CREDENTIAL.into(),
            data: sd_kbt,
        });
        Ok(SigningIdentity::new(credential, self.signature_pk.clone()))
    }

    pub fn update_sd_cwt(&mut self, sd_cwt: SdCwt) -> MlsResult<()> {
        let signer = self.signature_sk.as_bytes().to_vec();
        let alg = self.signature_algorithm()?;
        let sd_cwt = sd_cwt.to_cbor_bytes()?;
        let verified_sd_cwt = verify_sd_cwt(&sd_cwt, signer, alg, &self.auth_cks()?)?.as_ref().clone();

        self.delegate_mut()?.config_mut().set_sd_cwt(verified_sd_cwt);

        Ok(())
    }

    pub fn sd_cwt(&self) -> MlsResult<&VerifiedSdCwt> {
        Ok(&self.delegate()?.config().sd_cwt)
    }

    pub fn sd_cwt_mut(&mut self) -> MlsResult<&mut VerifiedSdCwt> {
        Ok(&mut self.delegate_mut()?.config_mut().sd_cwt)
    }

    pub fn identity_provider(&self) -> MlsResult<ProtonMeetIdentityProvider> {
        Ok(self.delegate()?.identity_provider())
    }

    pub fn auth_cks(&self) -> MlsResult<CoseKeySet> {
        Ok(self.identity_provider()?.auth_cks.as_ref().clone())
    }

    pub fn server_cks(&self) -> MlsResult<CoseKeySet> {
        Ok(self.identity_provider()?.server_cks.as_ref().clone())
    }

    /// Computes the adequate role for a joiner either via external join proposal or external commit
    fn role_for_external_joiner(
        group_info: &GroupInfoRef<'_>,
        signing_identity: &SigningIdentity,
        active_participants: HashSet<UserIdentifier>,
    ) -> MlsResult<Option<AppDataUpdateProposal>> {
        let Some(application_data) = group_info.context().extensions().application_data_spec()? else {
            return Err(MimiPolicyError::AuthorizerError(AuthorizerError::MissingApplicationData).into());
        };
        let current_identity = ProtonMeetIdentityProvider::identity_from_signing_identity(signing_identity)?;
        let claim_extractor = ProtonMeetClaimExtractor::new(signing_identity.credential.clone())?;

        Ok(role_proposal_for_external_join(
            application_data,
            &current_identity,
            &claim_extractor,
            active_participants,
        )?
        .map(|c| AppDataUpdateProposal {
            component_id: c.component_id,
            op: AppDataUpdateOperation::Update(c.data),
        }))
    }
}

// delegate pattern
impl<Kv: KvExt + Send + Sync + Clone + Debug> MlsClientTrait for MlsClient<Kv, Initialized> {
    type Kv = Kv;

    async fn new_group(
        &self,
        id: &GroupId,
        disclosure: Disclosure,
        group_config: MlsGroupConfig,
    ) -> MlsResult<MlsGroup<Self::Kv, Uninitialized>> {
        let room_id = group_config.room_id()?;
        let si = self.new_signing_identity(disclosure, &PresentationContext::CreateGroup { room_id })?;
        let group_extensions = group_config.group_context_extensions()?;

        let leaf_node_extensions = self.config.leaf_node_extensions()?;
        let group = self
            .delegate()?
            .create_group_with(id.to_bytes(), group_extensions, leaf_node_extensions, &si)
            .await?;
        Ok(MlsGroup(Box::new(group), Default::default()))
    }

    async fn load_groups(&self, groups: &[MlsGroupEntity]) -> MlsResult<Vec<MlsGroup<Self::Kv>>> {
        use futures_util::StreamExt as _;

        futures_util::stream::iter(groups)
            .then(|g| self.load_group(g))
            .collect::<Vec<MlsResult<_>>>()
            .await
            .into_iter()
            .collect::<MlsResult<Vec<_>>>()
    }

    async fn load_group(&self, group: &MlsGroupEntity) -> MlsResult<MlsGroup<Self::Kv>> {
        // TODO this is a quite suboptimal way to load groups.
        // We have all the groups given as parameters but we are still asking mls-rs to re-fetch them from the DB.
        //
        // Instead we should try to do `Snapshot::mls_decode(&mut &*group)` and `Group::from_snapshot()`
        let snapshot = mls_rs::group::snapshot::Snapshot::mls_decode(&mut &*group.state.data)?;
        let group = mls_rs::Group::from_snapshot(self.delegate()?.config().clone(), snapshot).await?;
        Ok(MlsGroup(Box::new(group), Default::default()))
    }

    async fn new_key_packages(
        &self,
        quantity: u32,
        disclosure: Disclosure,
    ) -> MlsResult<(Vec<KeyPackage>, core::time::Duration)> {
        if quantity == 0 {
            return Ok((vec![], core::time::Duration::from_secs(0)));
        }

        let si = self.new_signing_identity(disclosure, &PresentationContext::NewKeyPackage)?;

        let kp_extensions = self.config.key_package_extensions()?;
        let leaf_node_extensions = self.config.leaf_node_extensions()?;

        let kps = self
            .delegate()?
            .generate_key_package_messages(kp_extensions, leaf_node_extensions, quantity as usize, &si)
            .await?;

        let kps = kps
            .into_iter()
            .map(|m| MlsMessage::from(m).try_into())
            .collect::<Result<Vec<KeyPackage>, _>>()?;

        let expiration = kps.first().map(KeyPackage::expiry).transpose()?.unwrap_or_default();

        Ok((kps, expiration))
    }

    async fn join_group(
        &self,
        welcome: MlsMessage,
        ratchet_tree: PublicRatchetTree,
    ) -> MlsResult<(MlsGroup<Self::Kv, Uninitialized>, ReceivedNewMemberMessage)> {
        let maybe_time = welcome.virtual_time().map(time_to_mlsrs_time);
        let (group, new_member_info) = self
            .delegate()?
            .join_group(Some(ratchet_tree.into()), &welcome.into(), maybe_time)
            .await?;
        Ok((
            MlsGroup(Box::new(group), Default::default()),
            new_member_info.try_into()?,
        ))
    }

    async fn examine_welcome_message(&self, message: &MlsMessage) -> MlsResult<GroupInfo> {
        self.delegate()?
            .examine_welcome_message(message.as_inner())
            .await
            .map(Into::into)
            .map_err(Into::into)
    }

    async fn join_group_via_external_commit(
        &self,
        group_info: MlsMessage,
        ratchet_tree: PublicRatchetTree,
        disclosure: Disclosure,
        external_psks: Vec<ExternalPskId>,
    ) -> MlsResult<(MlsGroup<Self::Kv, Uninitialized>, CommitBundle)> {
        // Extract typed group info
        let gi = group_info.as_group_info().ok_or_else(|| MlsError::GroupInfoExpected)?;
        let room_metadata = gi
            .room_metadata()?
            .ok_or(MlsError::ImplementationError("Only MIMI groups are supported"))?;
        let room_id = room_metadata.room_uri.uri.parse()?;

        let si = self.new_signing_identity(disclosure, &PresentationContext::JoinGroupExternalCommit { room_id })?;

        let exported_tree: ExportedTree = ratchet_tree.into();
        let active_participants = exported_tree
            .members_iter()
            .map(|member| ProtonMeetIdentityProvider::identity_from_signing_identity(&member.signing_identity))
            .collect::<Result<HashSet<UserIdentifier>, _>>()?;
        let role_proposal = Self::role_for_external_joiner(&gi, &si, active_participants)?;

        let builder = |is_resync: bool| {
            let leaf_node_extensions = self.config.leaf_node_extensions()?;
            let mut builder = ExternalCommitBuilder::new(
                self.signature_sk.clone(),
                si.clone(),
                self.delegate()?.config().to_owned(),
            )
            .with_tree_data(exported_tree.clone())
            .with_leaf_node_extensions(leaf_node_extensions);
            for external_psk_id in &external_psks {
                builder = builder.with_external_psk(external_psk_id.clone().into());
            }
            if let Some(proposal) = role_proposal.as_ref().filter(|_| !is_resync) {
                // in case we do a resync (we rejoin the group removing our previous LeafNode,
                // we keep the same role hence we do not need an ADU proposal)
                builder = builder.with_application_data_update(proposal.clone())?;
            }
            MlsResult::Ok(builder)
        };
        let (group, ext_commit) = match builder(false)?.build(group_info.clone().into()).await {
            Ok(v) => v,
            //
            // /!\ FIXME /!\
            //
            // This is a workaround for re-joining groups since mls-rs doesn't
            // automatically insert a self remove proposal if self is already
            // a member of the group.
            //
            Err(mls_rs::client::MlsError::DuplicateLeafData(idx)) => {
                builder(true)?.with_removal(idx).build(group_info.into()).await?
            }
            Err(e) => return Err(e.into()),
        };

        let group_info = Some(group.group_info_message_allowing_ext_commit(false).await?.into());
        let ratchet_tree = Some(group.export_tree().into_owned().into());

        let bundle = CommitBundle {
            commit: ext_commit.into(),
            group_info,
            ratchet_tree,
            welcome: None,
            contains_update_path: true, // external commits always do
        };

        Ok((MlsGroup(Box::new(group), Default::default()), bundle))
    }

    async fn join_via_external_proposal(
        &self,
        group_info: MlsMessage,
        ratchet_tree: PublicRatchetTree,
        disclosure: Disclosure,
    ) -> MlsResult<MlsMessage> {
        let gi = group_info.as_group_info().ok_or_else(|| MlsError::GroupInfoExpected)?;

        let room_metadata = gi
            .room_metadata()?
            .ok_or(MlsError::ImplementationError("Only MIMI groups are supported"))?;
        let room_id = room_metadata.room_uri.uri.parse()?;

        let si = self.new_signing_identity(disclosure, &PresentationContext::JoinGroupExternalProposal { room_id })?;

        let rt = Some(ratchet_tree.into());

        let leaf_node_extensions = self.config.as_ref().leaf_node_extensions()?;
        let kp_extensions = self.config.as_ref().key_package_extensions()?;

        let maybe_time = group_info.virtual_time().map(time_to_mlsrs_time);

        Ok(self
            .delegate()?
            .external_add_proposal_with(
                &group_info.into(),
                rt,
                vec![],
                kp_extensions,
                leaf_node_extensions,
                Some(&si),
                maybe_time,
            )
            .await?
            .into())
    }

    #[cfg(feature = "external-sender")]
    async fn propose_external_remove(
        &self,
        leaf_index: meet_identifiers::LeafIndex,
        group_info: MlsMessage,
        ratchet_tree: PublicRatchetTree,
        signer: Option<Vec<u8>>,
    ) -> MlsResult<MlsMessage> {
        let maybe_time = group_info.virtual_time().map(time_to_mlsrs_time);

        let gi = group_info.as_group_info().ok_or_else(|| MlsError::GroupInfoExpected)?;

        // only used for testing, we pick the first external sender and try to impersonate him
        let ext_sender = gi.external_senders()?.remove(0);
        let si = SigningIdentity {
            signature_key: ext_sender.signature_key.to_vec().into(),
            credential: mls_types::Credential::try_from(ext_sender.credential.clone())?.try_into()?,
        };

        let signer = signer.map(Into::into).unwrap_or_else(|| self.signature_sk.clone());

        let delegate = self.delegate()?;
        let ext_client = mls_rs::external_client::ExternalClient::builder()
            .signer(signer, si)
            .identity_provider(self.identity_provider()?)
            .crypto_provider(delegate.crypto_provider())
            .build();

        let rt = Some(ratchet_tree.into());

        let mut ext_group = ext_client.observe_group(group_info.into(), rt, maybe_time).await?;

        let proposal = ext_group.propose_remove(*leaf_index, vec![]).await?.into();
        Ok(proposal)
    }

    async fn new_ephemeral_hpke_keypair(&self) -> MlsResult<HpkeKeyPair> {
        let crypto_provider = self.delegate()?.crypto_provider();
        let cs_provider =
            crypto_provider
                .cipher_suite_provider(self.cs.into())
                .ok_or(MlsError::ImplementationError(
                    "A client had not ciphersuite provider initialized",
                ))?;
        let (sk, pk) = cs_provider.kem_generate().await?;
        Ok(HpkeKeyPair {
            hpke_public_key: pk.into(),
            hpke_secret_key: sk.into(),
        })
    }

    async fn try_sign(&self, tbs: &[u8], label: &str) -> MlsResult<Signature> {
        let crypto_provider = self.delegate()?.crypto_provider();
        let cs_provider =
            crypto_provider
                .cipher_suite_provider(self.cs.into())
                .ok_or(MlsError::ImplementationError(
                    "A client had not ciphersuite provider initialized",
                ))?;
        let sign_content = SignContent::new_with_raw_label(label, tbs.to_vec());
        let tbs = sign_content.mls_encode_to_vec()?;

        let signature = cs_provider.sign(&self.signature_sk, &tbs[..]).await?;

        Ok(signature.into())
    }

    async fn verify_signature(&self, public_key: &[u8], signature: &[u8], tbs: &[u8], label: &str) -> MlsResult<()> {
        let crypto_provider = self.delegate()?.crypto_provider();
        let cs_provider =
            crypto_provider
                .cipher_suite_provider(self.cs.into())
                .ok_or(MlsError::ImplementationError(
                    "A client had not ciphersuite provider initialized",
                ))?;
        let sign_content = SignContent::new_with_raw_label(label, tbs.to_vec());
        let tbs = sign_content.mls_encode_to_vec()?;

        let public_key = mls_rs::crypto::SignaturePublicKey::new_slice(public_key);

        cs_provider.verify(&public_key, signature, &tbs).await?;

        Ok(())
    }

    async fn hpke_decrypt(
        &self,
        mut hpke_ciphertext: &[u8],
        keypair: HpkeKeyPair,
        label: &str,
        context: &[u8],
    ) -> MlsResult<Vec<u8>> {
        let ciphertext = mls_rs_core::crypto::HpkeCiphertext::mls_decode(&mut hpke_ciphertext)?;
        let crypto_provider = self.delegate()?.crypto_provider();
        let cs_provider =
            crypto_provider
                .cipher_suite_provider(self.cs.into())
                .ok_or(MlsError::ImplementationError(
                    "A client had not ciphersuite provider initialized",
                ))?;
        let info = EncryptContext::new_with_raw_label(label, context).mls_encode_to_vec()?;
        let mut hpke_ctx = cs_provider
            .hpke_setup_r(
                &ciphertext.kem_output,
                &keypair.hpke_secret_key.into(),
                &keypair.hpke_public_key.into(),
                &info,
            )
            .await?;
        let decrypted = hpke_ctx
            .open(None, &ciphertext.ciphertext)
            .await
            .map_err(IntoAnyError::into_any_error)?;
        Ok(decrypted)
    }

    fn new_identity_presentation(
        &self,
        disclosure: Disclosure,
        user_asserted: Option<UserAsserted>,
        ctx: &PresentationContext,
    ) -> MlsResult<Vec<u8>> {
        let signer = self.signature_sk.as_bytes();
        let alg = self.signature_algorithm()?;
        let sd_cwt = self.sd_cwt()?;
        let sd_kbt = new_identity_presentation(signer, alg, sd_cwt.clone(), disclosure, user_asserted, ctx)?;
        Ok(sd_kbt)
    }

    fn random_bytes(&self, buf: &mut [u8]) -> MlsResult<()> {
        self.delegate()?
            .crypto_provider()
            .cipher_suite_provider(self.cs.into())
            .ok_or_else(|| MlsError::ImplementationError("no ciphersuiteprovider found for cs."))?
            .random_bytes(buf)
            .map_err(MlsError::CryptoError)
    }

    fn ciphersuite(&self) -> CipherSuite {
        self.cs
    }

    fn credential_type(&self) -> CredentialType {
        self.ct
    }

    fn signature_public_key(&self) -> &[u8] {
        self.signature_pk.as_bytes()
    }

    async fn all_key_package_entities(&self) -> MlsResult<Vec<MlsKeyPackageEntity>> {
        Ok(self
            .delegate()?
            .key_package_store()
            .get_all::<MlsKeyPackageEntity>()
            .await?)
    }

    async fn all_key_packages(&self) -> MlsResult<impl Iterator<Item = KeyPackage>> {
        Ok(self.all_key_package_entities().await?.into_iter().filter_map(|kp| {
            use mls_rs_codec::MlsDecode as _;
            KeyPackage::mls_decode(&mut kp.value.key_package_bytes.as_slice()).ok()
        }))
    }

    async fn purge_key_packages_by_ref(&self, kp_refs: Vec<&KeyPackageRef>) -> MlsResult<()> {
        self.delegate()?
            .key_package_store()
            .remove_all::<MlsKeyPackageEntity>(kp_refs.into_iter().map(|kp| kp.as_ref().into()))
            .await
            .map_err(MlsError::from)
    }

    async fn insert_external_psk(&self, id: ExternalPskId, psk: ExternalPsk) -> MlsResult<()> {
        let id = mls_rs::psk::ExternalPskId::from(id);
        let psk = mls_rs::psk::PreSharedKey::from(psk);
        let store = self.delegate()?.config().secret_store();
        Ok(store.insert_external_psk(id, psk).await?)
    }

    async fn remove_external_psk(&self, id: &ExternalPskId) -> MlsResult<()> {
        let id = mls_rs::psk::ExternalPskId::from(id.clone());
        let store = self.delegate()?.config().secret_store();
        Ok(store.remove_external_psk(&id).await?)
    }

    async fn has_external_psk(&self, id: &ExternalPskId) -> MlsResult<bool> {
        let id = mls_rs::psk::ExternalPskId::from(id.clone());
        let store = self.delegate()?.config().secret_store();
        Ok(store.contains_external_psk(&id).await?)
    }

    fn user_id(&self) -> MlsResult<UserId> {
        Ok(self.sd_cwt()?.clone().user_id()?)
    }
}

impl<Kv: KvExt + Send + Sync + Clone, S: MlsClientState> MlsClient<Kv, S> {
    fn signature_algorithm(&self) -> MlsResult<identity::SignatureAlgorithm> {
        Ok(match self.cs.signature_alg() {
            SignatureAlgorithm::Ed25519 => identity::SignatureAlgorithm::Ed25519,
            SignatureAlgorithm::P256 => identity::SignatureAlgorithm::P256,
            SignatureAlgorithm::P384 => identity::SignatureAlgorithm::P384,
            SignatureAlgorithm::Ed448 | SignatureAlgorithm::P521 => {
                return Err(MlsError::ImplementationError(
                    "signature alg not yet supported for selective identity disclosure",
                ));
            }
        })
    }

    pub fn new_mls_rs_client(
        mls_client_config: StdMlsClientConfig<Kv>,
        config: &MlsClientConfig,
        cs: CipherSuite,
        signature_sk: mls_rs_core::crypto::SignatureSecretKey,
    ) -> mls_rs::Client<StdMlsClientConfig<Kv>> {
        let protocol_version = config.protocol_version.into();
        mls_rs::Client::new(mls_client_config, Some(signature_sk), cs.into(), None, protocol_version)
    }

    pub fn get_holder_confirmation_key_pem(&self) -> MlsResult<String> {
        Ok(match self.cs.signature_alg() {
            SignatureAlgorithm::Ed25519 => {
                let vk = self.signature_pk.as_bytes().try_into()?;
                let vk = ed25519_dalek::VerifyingKey::from_bytes(&vk)?;
                use ed25519_dalek::pkcs8::EncodePublicKey as _;
                vk.to_public_key_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)?
            }
            _ => return Err(MlsError::ImplementationError("Other ciphersuites not yet implemented")),
        })
    }
}

#[cfg(feature = "test-utils")]
impl<Kv> Clone for MlsClient<Kv, Initialized>
where
    Kv: KvExt + Clone + Send + Sync,
{
    fn clone(&self) -> Self {
        Self {
            delegate: self.delegate.clone(),
            cs: self.cs,
            ct: self.ct,
            signature_pk: self.signature_pk.clone(),
            signature_sk: self.signature_sk.clone(),
            config: self.config.clone(),
            _state: self._state,
        }
    }
}

impl<Kv> Eq for MlsClient<Kv, Initialized> where Kv: KvExt + Clone + Send + Sync {}

impl<Kv> PartialEq for MlsClient<Kv, Initialized>
where
    Kv: KvExt + Clone + Send + Sync,
{
    fn eq(&self, other: &Self) -> bool {
        self.signature_sk.eq(&other.signature_sk)
            && self.cs.eq(&other.cs)
            && self.ct.eq(&other.ct)
            && self.signature_pk.eq(&other.signature_pk)
    }
}

impl<Kv> Hash for MlsClient<Kv, Initialized>
where
    Kv: KvExt + Send + Sync,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.cs.hash(state);
        self.ct.hash(state);
    }
}
