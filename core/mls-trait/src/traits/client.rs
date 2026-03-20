use crate::types::ReceivedNewMemberMessage;
use identity::{Disclosure, PresentationContext};
use meet_identifiers::{GroupId, UserId};
use mls_types::{
    CipherSuite, CredentialType, ExternalPsk, ExternalPskId, GroupInfo, GroupInfoRef, HpkeKeyPair, KeyPackage,
    KeyPackageRef, MlsMessage, PublicRatchetTree, Signature,
};
use proton_claims::{UserAsserted, reexports::CwtAny as _};

#[cfg(feature = "wickr")]
pub use crate::wickr::client::MlsClient;

use crate::{
    CommitBundle, KvExt, MlsError, MlsGroup, MlsGroupEntity, MlsKeyPackageEntity, MlsResult, Uninitialized,
    traits::config::MlsGroupConfig,
};

/// Since the KeyPackage must be more ephemeral than the credential it wraps (in out case an SD-CWT), we will
/// decrease the KP lifetime by this leeway
#[cfg(not(any(test, feature = "test-utils")))]
pub const KEY_PACKAGE_EXP_LEEWAY: core::time::Duration = core::time::Duration::from_secs(60); // 1m
#[cfg(any(test, feature = "test-utils"))]
pub const KEY_PACKAGE_EXP_LEEWAY: core::time::Duration = core::time::Duration::from_secs(0);

#[allow(private_bounds, async_fn_in_trait)]
pub trait MlsClientTrait {
    type Kv: KvExt + Send + Sync + Clone;

    async fn new_group(
        &self,
        id: &GroupId,
        disclosure: Disclosure,
        group_config: MlsGroupConfig,
    ) -> MlsResult<MlsGroup<Self::Kv, Uninitialized>>;

    async fn new_key_packages(
        &self,
        quantity: u32,
        disclosure: Disclosure,
    ) -> MlsResult<(Vec<KeyPackage>, core::time::Duration)>;

    async fn count_key_packages(&self) -> MlsResult<u32> {
        let owner = self.user_id()?;
        let count = self
            .all_key_packages()
            .await?
            .filter_map(|kp| {
                let mut c = mls_types::Credential::try_from(kp.leaf_node.signing_identity.credential.clone()).ok()?;
                let user_id = c.user_id().ok()?;
                let (cs, ct) = (kp.ciphersuite().ok()?, kp.credential_type().ok()?);
                (owner == user_id && cs == self.ciphersuite() && ct == self.credential_type()).then_some(())
            })
            .count();
        Ok(count as u32)
    }

    async fn all_key_package_ref(&self) -> MlsResult<Vec<KeyPackageRef>> {
        self.all_key_package_entities()
            .await?
            .iter()
            .map(|kp| kp.kp_ref())
            .collect::<MlsResult<_>>()
    }

    async fn all_key_package_entities(&self) -> MlsResult<Vec<MlsKeyPackageEntity>>;

    async fn all_key_packages(&self) -> MlsResult<impl Iterator<Item = KeyPackage>>;

    async fn purge_key_packages_by_ref(&self, kp_refs: Vec<&KeyPackageRef>) -> MlsResult<()>;

    async fn insert_external_psk(&self, id: ExternalPskId, psk: ExternalPsk) -> MlsResult<()>;

    async fn remove_external_psk(&self, id: &ExternalPskId) -> MlsResult<()>;

    async fn has_external_psk(&self, id: &ExternalPskId) -> MlsResult<bool>;

    fn user_id(&self) -> MlsResult<UserId>;

    async fn examine_welcome_message(&self, message: &MlsMessage) -> MlsResult<GroupInfo>;

    async fn join_group(
        &self,
        welcome: MlsMessage,
        ratchet_tree: PublicRatchetTree,
    ) -> MlsResult<(
        MlsGroup<<Self as MlsClientTrait>::Kv, Uninitialized>,
        ReceivedNewMemberMessage,
    )>;

    async fn new_ephemeral_hpke_keypair(&self) -> MlsResult<HpkeKeyPair>;

    async fn hpke_decrypt(
        &self,
        encrypted: &[u8],
        keypair: HpkeKeyPair,
        label: &str,
        context: &[u8],
    ) -> MlsResult<Vec<u8>>;

    async fn try_sign(&self, tbs: &[u8], label: &str) -> MlsResult<Signature>;

    async fn verify_signature(&self, public_key: &[u8], signature: &[u8], tbs: &[u8], label: &str) -> MlsResult<()>;

    async fn join_group_via_external_commit(
        &self,
        group_info: MlsMessage,
        ratchet_tree: PublicRatchetTree,
        disclosure: Disclosure,
        external_psks: Vec<ExternalPskId>,
    ) -> MlsResult<(MlsGroup<<Self as MlsClientTrait>::Kv, Uninitialized>, CommitBundle)>;

    async fn join_via_external_proposal(
        &self,
        group_info: MlsMessage,
        ratchet_tree: PublicRatchetTree,
        disclosure: Disclosure,
    ) -> MlsResult<MlsMessage>;

    #[cfg(feature = "external-sender")]
    async fn propose_external_remove(
        &self,
        leaf_index: meet_identifiers::LeafIndex,
        group_info: MlsMessage,
        ratchet_tree: PublicRatchetTree,
        signer: Option<Vec<u8>>,
    ) -> MlsResult<MlsMessage>;

    async fn load_groups(&self, groups: &[MlsGroupEntity]) -> MlsResult<Vec<MlsGroup<<Self as MlsClientTrait>::Kv>>>;

    /// Reads the MLS group associated with this client from the MLS database.
    /// We do this because mls-rs stores it as a blob.
    /// Should only be required at startup
    async fn load_group(&self, group: &MlsGroupEntity) -> MlsResult<MlsGroup<Self::Kv>>;

    /// Creates a new presentation of a SD-CWT also known as a SD-KBT
    fn new_identity_presentation(
        &self,
        disclosure: Disclosure,
        user_asserted: Option<UserAsserted>,
        ctx: &PresentationContext,
    ) -> MlsResult<Vec<u8>>;

    fn new_sd_kbt(
        &self,
        disclosure: Disclosure,
        user_asserted: Option<UserAsserted>,
        ctx: &PresentationContext,
    ) -> MlsResult<identity::SdKbt> {
        identity::SdKbt::from_cbor_bytes(&self.new_raw_sd_kbt(disclosure, user_asserted, ctx)?).map_err(MlsError::from)
    }

    fn new_raw_sd_kbt(
        &self,
        disclosure: Disclosure,
        user_asserted: Option<UserAsserted>,
        ctx: &PresentationContext,
    ) -> MlsResult<Vec<u8>> {
        self.new_identity_presentation(disclosure, user_asserted, ctx)
    }

    /// Fill a buffer with random bytes
    /// Useful for salt generation.
    fn random_bytes(&self, buf: &mut [u8]) -> MlsResult<()>;

    fn ciphersuite(&self) -> CipherSuite;

    fn credential_type(&self) -> CredentialType;

    fn signature_public_key(&self) -> &[u8];

    // In charge of generating a unique identifier to put in the AAD for correlating commit.
    // It's only used for logging purpose so it's fine if inaccurate and returns an empty array
    fn external_commit_id(&self, gi: &GroupInfoRef<'_>, remove: Option<u32>) -> [u8; 32] {
        use sha2::digest::Digest as _;

        let group_id = gi.group_id().map(|id| id.to_string()).unwrap_or_default();
        let epoch = gi.epoch();

        let cs = self.ciphersuite();
        let ct = self.credential_type();
        let pk = self.signature_public_key();

        let id = format!("external-commit-{group_id}-{epoch}-{cs}-{ct}-{pk:x?}-{remove:?}");
        sha2::Sha256::digest(&id[..]).into()
    }

    // In charge of generating a unique identifier to put in the AAD for correlating external proposals.
    // It's only used for logging purpose so it's fine if inaccurate and returns an empty array
    fn external_proposal_id(&self, gi: &GroupInfoRef<'_>) -> [u8; 32] {
        use sha2::digest::Digest as _;

        let group_id = gi.group_id().map(|id| id.to_string()).unwrap_or_default();
        let epoch = gi.epoch();

        let cs = self.ciphersuite();
        let ct = self.credential_type();
        let pk = self.signature_public_key();

        let id = format!("external-proposal-{group_id}-{epoch}-{cs}-{ct}-{pk:x?}");
        sha2::Sha256::digest(&id[..]).into()
    }
}
