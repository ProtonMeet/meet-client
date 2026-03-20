use crate::mls_spec;
use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};

const CT_APPLICATION: u8 = mls_spec::messages::ContentType::Application as u8;
const CT_PROPOSAL: u8 = mls_spec::messages::ContentType::Proposal as u8;
const CT_COMMIT: u8 = mls_spec::messages::ContentType::Commit as u8;

#[derive(Copy, Clone, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode)]
#[repr(u8)]
pub enum ContentType {
    Application = CT_APPLICATION,
    Proposal = CT_PROPOSAL,
    Commit = CT_COMMIT,
}

impl std::fmt::Display for ContentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ct = match self {
            Self::Application => "Application",
            Self::Proposal => "Proposal",
            Self::Commit => "Commit",
        };
        write!(f, "{ct}")
    }
}
