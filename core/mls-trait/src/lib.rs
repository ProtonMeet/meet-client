mod error;
mod kv;
mod traits;
pub mod types;
#[cfg(feature = "wickr")]
pub mod wickr;

pub use {
    meet_mls::reexports::{
        meet_policy,
        mimi_protocol_mls::{
            self,
            reexports::{mls_spec, tls_codec},
        },
        mimi_room_policy,
    },
    error::{MlsError, MlsResult, SuccessorError},
    kv::{Entity, InsertOutput, KvError, KvExt, MlsEntity, SignaturePK},
    traits::{
        client::{MlsClient, MlsClientTrait},
        config::{CommonMlsGroupConfig, MlsClientConfig, MlsGroupConfig},
        crypto::MlsCryptoTrait,
        group::{MlsGroup, MlsGroupPendingReInitTrait, MlsGroupTrait},
        identity_arg::DeviceIdentityArg,
    },
    types::{
        AppliedProposal, Caniuse, ClaimsetDiff, ClientIdentity, CommitBundle, CommitOutput, ParticipantListEffect,
        ProposalArg, ProposalEffect, ReceiverReInitOutput, SenderReInitOutput, UserIdRolePair,
    },
    // FIXME: this should not be exposed like that because this mod is feature gated
    wickr::{
        authorization::{
            Authorizer, AuthorizerExt, UserAuthorizationInfo, authorization_info, preauth_claim_condition,
        },
        identity::ProtonMeetIdentityProvider,
        kv::{MlsGroupEntity, MlsIdentityEntity, MlsKeyPackageEntity, MlsPskEntity},
    },
};

pub trait MlsClientState {}
pub trait MlsGroupState {}

/// Ready to be used
#[derive(Debug, Clone)]
pub struct Initialized;
/// Not yet ready to be used, requires one initialization step
#[derive(Debug, Clone)]
pub struct Uninitialized;

#[derive(Debug, Clone)]
pub struct PendingReInit;

impl MlsClientState for Initialized {}
impl MlsClientState for Uninitialized {}

impl MlsGroupState for Initialized {}
impl MlsGroupState for Uninitialized {}
impl MlsGroupState for PendingReInit {}

/// Number of previous epochs retention, used to continue decrypting ApplicationMessages arriving
/// out-of-order, for example if the sender is on a slow connection
pub const MAX_EPOCH_RETENTION: usize = 3;
