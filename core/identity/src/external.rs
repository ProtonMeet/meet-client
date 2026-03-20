use crate::{ExternalSenderSdKbt, IdentityResult};
use meet_identifiers::Domain;

pub fn validate_external_sender_sd_kbt(_sd_kbt: &ExternalSenderSdKbt, _domain: &Domain) -> IdentityResult<()> {
    // TODO: but not urgent
    // verify self-issued: cnf in sd-cwt should also verify sd-cwt signature
    // domain of the sub is the expected one
    // domain of the issuer is the expected one
    // domain of the audience is the expected one
    // all the rest of validations
    Ok(())
}
