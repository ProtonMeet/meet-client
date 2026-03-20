use crate::{MlsTypesError, Proposal};
use mls_rs::group::proposal::Proposal as MlsProposal;

impl TryFrom<MlsProposal> for Proposal {
    type Error = MlsTypesError;

    fn try_from(value: MlsProposal) -> Result<Self, Self::Error> {
        let prop = match value {
            MlsProposal::Add(add_proposal) => Self::Add(*add_proposal),
            MlsProposal::Update(update_proposal) => Self::Update(update_proposal),
            MlsProposal::Remove(remove_proposal) => Self::Remove(remove_proposal),
            MlsProposal::Psk(pre_shared_key_proposal) => Self::Psk(pre_shared_key_proposal),
            MlsProposal::ReInit(re_init_proposal) => Self::ReInit(re_init_proposal),
            MlsProposal::ExternalInit(external_init) => Self::ExternalInit(external_init),
            MlsProposal::GroupContextExtensions(extension_list) => Self::GroupContextExtensions(extension_list),
            MlsProposal::AppDataUpdate(application_data_update_proposal) => {
                Self::AppDataUpdate(application_data_update_proposal)
            }
            MlsProposal::AppEphemeral(app_ephemeral) => Self::AppEphemeral(app_ephemeral),
            _ => return Err(MlsTypesError::ImplementationError("Not Implemented")),
        };
        Ok(prop)
    }
}

#[inline(always)]
pub fn mls_spec_to_mls_rs(value: crate::mls_spec::defs::ProposalType) -> mls_rs::group::proposal::ProposalType {
    mls_rs::group::proposal::ProposalType::from(*value)
}
