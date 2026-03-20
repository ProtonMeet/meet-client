use std::fmt::Debug;

use mls_rs::group::proposal::ProposalType;
use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};

// TODO: own this type
pub enum Proposal {
    Add(mls_rs::group::proposal::AddProposal),
    Remove(mls_rs::group::proposal::RemoveProposal),
    Update(mls_rs::group::proposal::UpdateProposal),
    Psk(mls_rs::group::proposal::PreSharedKeyProposal),
    ReInit(mls_rs::group::proposal::ReInitProposal),
    ExternalInit(mls_rs::group::proposal::ExternalInit),
    GroupContextExtensions(mls_rs::ExtensionList),
    AppDataUpdate(mls_rs::group::proposal::AppDataUpdateProposal),
    AppEphemeral(mls_rs::group::proposal::AppEphemeralProposal),
}

impl Proposal {
    fn proposal_type(&self) -> ProposalType {
        match self {
            Self::Add(_) => ProposalType::ADD,
            Self::Remove(_) => ProposalType::REMOVE,
            Self::Update(_) => ProposalType::UPDATE,
            Self::Psk(_) => ProposalType::PSK,
            Self::ReInit(_) => ProposalType::RE_INIT,
            Self::ExternalInit(_) => ProposalType::EXTERNAL_INIT,
            Self::GroupContextExtensions(_) => ProposalType::GROUP_CONTEXT_EXTENSIONS,
            Self::AppDataUpdate(_) => ProposalType::APP_DATA_UPDATE,
            Self::AppEphemeral(_) => ProposalType::APP_EPHEMERAL,
        }
    }

    pub fn to_remove_index(self) -> Option<u32> {
        match self {
            Self::Remove(r) => Some(r.to_remove()),
            _ => None,
        }
    }
}

impl Debug for Proposal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Add(_) => "Proposal::Add",
                Self::Remove(_) => "Proposal::Remove",
                Self::Update(_) => "Proposal::Update",
                Self::Psk(_) => "Proposal::Psk",
                Self::ReInit(_) => "Proposal::ReInit",
                Self::ExternalInit(_) => "Proposal::ExternalInit",
                Self::GroupContextExtensions(_) => "Proposal::GroupContenxtExtensions",
                Self::AppDataUpdate(_) => "Proposal::AppDataUpdate",
                Self::AppEphemeral(_) => "Proposal::AppEphemeral",
            }
        )
    }
}

impl MlsSize for Proposal {
    fn mls_encoded_len(&self) -> usize {
        let l = match self {
            Self::Add(p) => p.mls_encoded_len(),
            Self::Remove(p) => p.mls_encoded_len(),
            Self::Update(p) => p.mls_encoded_len(),
            Self::Psk(p) => p.mls_encoded_len(),
            Self::ReInit(p) => p.mls_encoded_len(),
            Self::ExternalInit(p) => p.mls_encoded_len(),
            Self::GroupContextExtensions(p) => p.mls_encoded_len(),
            Self::AppDataUpdate(p) => p.mls_encoded_len(),
            Self::AppEphemeral(p) => p.mls_encoded_len(),
        };
        l + self.proposal_type().mls_encoded_len()
    }
}

impl MlsEncode for Proposal {
    fn mls_encode(&self, writer: &mut Vec<u8>) -> Result<(), mls_rs_codec::Error> {
        self.proposal_type().mls_encode(writer)?;
        match self {
            Self::Add(p) => p.mls_encode(writer),
            Self::Remove(p) => p.mls_encode(writer),
            Self::Update(p) => p.mls_encode(writer),
            Self::Psk(p) => p.mls_encode(writer),
            Self::ReInit(p) => p.mls_encode(writer),
            Self::ExternalInit(p) => p.mls_encode(writer),
            Self::GroupContextExtensions(p) => p.mls_encode(writer),
            Self::AppDataUpdate(p) => p.mls_encode(writer),
            Self::AppEphemeral(p) => p.mls_encode(writer),
        }
    }
}

impl MlsDecode for Proposal {
    fn mls_decode(reader: &mut &[u8]) -> Result<Self, mls_rs_codec::Error> {
        let proposal_type = ProposalType::mls_decode(reader)?;

        Ok(match proposal_type {
            ProposalType::ADD => Self::Add(mls_rs::group::proposal::AddProposal::mls_decode(reader)?),
            ProposalType::UPDATE => Self::Update(mls_rs::group::proposal::UpdateProposal::mls_decode(reader)?),
            ProposalType::REMOVE => Self::Remove(mls_rs::group::proposal::RemoveProposal::mls_decode(reader)?),
            ProposalType::PSK => Self::Psk(mls_rs::group::proposal::PreSharedKeyProposal::mls_decode(reader)?),
            ProposalType::RE_INIT => Self::ReInit(mls_rs::group::proposal::ReInitProposal::mls_decode(reader)?),
            ProposalType::EXTERNAL_INIT => {
                Self::ExternalInit(mls_rs::group::proposal::ExternalInit::mls_decode(reader)?)
            }
            ProposalType::GROUP_CONTEXT_EXTENSIONS => {
                Self::GroupContextExtensions(mls_rs::ExtensionList::mls_decode(reader)?)
            }
            ProposalType::APP_DATA_UPDATE => {
                Self::AppDataUpdate(mls_rs::group::proposal::AppDataUpdateProposal::mls_decode(reader)?)
            }
            ProposalType::APP_EPHEMERAL => {
                Self::AppEphemeral(mls_rs::group::proposal::AppEphemeralProposal::mls_decode(reader)?)
            }
            _ => return Err(mls_rs_codec::Error::Custom(3)),
        })
    }
}
