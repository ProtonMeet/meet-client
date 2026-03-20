use crate::meet_policy::UserRole;
use crate::mimi_protocol_mls::components::metadata::RoomMetadata;
use crate::{MlsError, traits::group::MlsGroupPendingReInitTrait};
use identity::SdKbt;
use meet_identifiers::{DeviceId, Epoch, GroupId, LeafIndex, UserId};
use mls_spec::drafts::mls_extensions::safe_application::{Component, ComponentId};
use mls_types::{
    Capabilities, CipherSuite, Credential, CredentialClaims, CredentialType, Extensions, ExternalPskId, KeyPackage,
    ProtocolVersion, SignaturePublicKey,
};
use std::collections::HashMap;

mod commit_bundle;
mod received_message;

pub use commit_bundle::CommitBundle;
pub use received_message::{PreviousGroupState, ReceivedMessage, ReceivedMessages, ReceivedNewMemberMessage};

/// Identity of an MLS client. It is not the identity of a user !
#[derive(Debug, Clone)]
pub struct ClientIdentity {
    pub credential: Credential,
    pub signature_public_key: SignaturePublicKey,
}

/// Output of an applied commit to a group
#[derive(Debug)]
pub struct CommitOutput {
    /// All applied proposals
    pub applied_proposals: Vec<AppliedProposal>,
    /// All local pending proposals
    pub unused_proposals: Vec<mls_types::Proposal>,
    /// Committer of `applied_proposals`
    pub committer: DeviceId,
    /// New epoch
    pub epoch: Epoch,
}

/// A proposal applied to a group
#[derive(Debug)]
pub struct AppliedProposal {
    /// Credential of the sender of that proposal
    pub sender: DeviceId,
    /// Effect of that proposal
    pub effect: ProposalEffect,
}

/// Effect of an applied proposal on the Model
#[derive(Debug, Clone, PartialEq)]
pub enum ProposalEffect {
    /// Updates an app component
    UpdateComponent {
        id: ComponentId,
        data: Vec<u8>,
    },
    /// updates to the metadata of the room
    UpdateRoomMetadata {
        metadata: RoomMetadata,
    },
    /// Update to our LeafNode
    Update {
        claimset_diff: ClaimsetDiff,
        new_credential: Credential,
    },
    /// updates to the participant list
    UpdateParticipantList {
        participants: ParticipantListEffect,
    },
    /// Removes an app component with the given id
    RemoveComponent(ComponentId),
    // TODO: Update {
    //    credential: Option<Credential>
    // }
    /// Removed the current group device
    SelfRemove(DeviceId),
    /// Removed the device with the given id
    Remove(DeviceId),
    /// Adds a new member to the group
    Add(Credential),
    /// A device joined with an external commit. The joined device is
    /// the proposal sender
    ExternalInit(Credential),
    /// The self user joined a room for the first time (it's the first device for this user that is added to the room)
    SelfExternalInit,
    // TODO: to refine which ones we care about, maybe none
    GroupContextExtensions,
    /// A new group was created, replacing the old one
    ReInit {
        new_group_id: GroupId,
        new_ciphersuite: Option<CipherSuite>,
        new_protocol_version: Option<ProtocolVersion>,
    },
    /// Adds a pre-shared key reference to the group
    PskAdded {
        reference: mls_types::PskReference,
    },
    /// Something in the MLS state but we do not yet map it
    Unknown,
}

impl ProposalEffect {
    pub fn discriminant(&self) -> u8 {
        match self {
            Self::UpdateComponent { .. } => 0x01,
            Self::RemoveComponent(_) => 0x02,
            Self::Update { .. } => 0x03,
            Self::Remove(_) => 0x04,
            Self::SelfRemove(_) => 0x05,
            Self::Add(_) => 0x06,
            Self::ExternalInit(_) => 0x07,
            Self::ReInit { .. } => 0x08,
            Self::UpdateRoomMetadata { .. } => 0x09,
            Self::UpdateParticipantList { .. } => 0x0A,
            Self::GroupContextExtensions => 0x0B,
            Self::PskAdded { .. } => 0x0C,
            Self::SelfExternalInit => 0x0E,
            Self::Unknown { .. } => 0xFF,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ParticipantListEffect {
    pub changed: Vec<UserIdRolePair>,
    pub removed: Vec<UserId>,
    pub added: Vec<UserIdRolePair>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UserIdRolePair {
    pub user: UserId,
    pub role: UserRole,
}

/// Args for proposal construction
#[derive(Debug)]
#[cfg_attr(feature = "test-utils", derive(Clone))]
pub enum ProposalArg {
    /// Remove the device at that index
    Remove(LeafIndex),
    /// Adds a new device to the group
    Add(Box<KeyPackage>),
    /// Adds an external pre-shared key reference to the commit
    PskExternal { id: ExternalPskId },
    /// Changes the LeafNode in the group. In case one just want to force PCS, supply None in lieu of the SD-KBT
    Update {
        credential: Option<Box<SdKbt>>,
        extensions: Option<Extensions>,
        capabilities: Option<Capabilities>,
    },
    /// Updates an app component
    UpdateComponent { id: ComponentId, data: Vec<u8> },
    /// Removes an app component with the given id
    RemoveComponent(ComponentId),
    /// Reinitializes the group with new presets
    ReInit {
        new_ciphersuite: Option<CipherSuite>,
        new_protocol_version: Option<ProtocolVersion>,
    },
    /// This is just the diff that will be merged into the current one.
    GroupContextExtension(mls_types::Extensions),
}

impl ProposalArg {
    #[inline]
    pub fn update_credential(credential: Box<SdKbt>) -> Self {
        Self::Update {
            credential: Some(credential),
            extensions: None,
            capabilities: None,
        }
    }

    /// Create a new `ProposalArg::UpdateComponent`.
    pub fn update_component<C: Component>(component: &C) -> Result<Self, MlsError> {
        let component = component.to_component_data().map_err(MlsError::MlsSpecError)?;
        Ok(Self::UpdateComponent {
            id: component.component_id,
            data: component.data,
        })
    }
}

#[derive(Debug, Clone)]
pub struct SenderReInitOutput<G: MlsGroupPendingReInitTrait + Clone> {
    /// A MlsGroup to use to apply the reinit
    pub group: G,
    /// All the UserId for which a KeyPackage has to be fetched in order to perform the ReInit
    pub user_ids: HashMap<CredentialType, UserId>,
    /// The ciphersuite of the new group
    pub ciphersuite: CipherSuite,
}

#[derive(Debug, Clone)]
pub struct ReceiverReInitOutput<G: MlsGroupPendingReInitTrait + Clone> {
    /// A MlsGroup to use to apply the reinit
    pub group: G,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Caniuse {
    /// Yes all the MLS clients supports this
    Yes,
    /// At least one MLS client per user supports this
    YesAtLeastOneClient,
    /// At least one user in the group does not support this
    No,
    /// Not sure whether this is supported or not
    Unsure,
}

#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub enum Diff {
    #[default]
    Unchanged,
    Changed,
}

impl Diff {
    #[inline(always)]
    pub const fn changed(self) -> bool {
        matches!(self, Self::Changed)
    }

    pub fn compare<T: PartialEq>(a: &T, b: &T) -> Self {
        if a.eq(b) { Self::Unchanged } else { Self::Changed }
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct ClaimsetDiff {
    pub handle: Diff,
    pub name: Diff,
    pub email: Diff,
    pub picture: Diff,
    pub workspace_id: Diff,
    pub workspace_role: Diff,
    pub about: Diff,
}

impl ClaimsetDiff {
    pub fn compute(new_creds: &CredentialClaims, others: &[CredentialClaims]) -> Self {
        let mut diff = Self::default();
        if let Some(most_recent_cwt) = others.iter().max_by_key(|c| c.cwt_issued_at)
            && new_creds.cwt_issued_at > most_recent_cwt.cwt_issued_at
        {
            diff.name = Diff::compare(&new_creds.name, &most_recent_cwt.name);
            diff.email = Diff::compare(&new_creds.email, &most_recent_cwt.email);
            diff.picture = Diff::compare(&new_creds.picture, &most_recent_cwt.picture);
            diff.workspace_role = Diff::compare(&new_creds.workspace_role, &most_recent_cwt.workspace_role);
        }
        if let Some(most_recent_kbt) = others.iter().max_by_key(|c| c.kbt_issued_at)
            && new_creds.kbt_issued_at > most_recent_kbt.kbt_issued_at
        {
            diff.about = Diff::compare(&new_creds.about, &most_recent_kbt.about);
        }
        diff
    }

    #[inline]
    pub fn any_changed(&self) -> bool {
        self.handle.changed()
            || self.name.changed()
            || self.email.changed()
            || self.picture.changed()
            || self.about.changed()
            || self.workspace_id.changed()
            || self.workspace_role.changed()
    }
}
