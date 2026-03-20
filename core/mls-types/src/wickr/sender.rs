use crate::{MlsTypesError, Sender};
use mls_rs::group::Sender as WickrSender;

impl From<Sender> for WickrSender {
    fn from(s: Sender) -> Self {
        match s {
            Sender::Member(m) => Self::Member(m),
            Sender::External(e) => Self::External(e),
            Sender::NewMemberProposal => Self::NewMemberProposal,
            Sender::NewMemberCommit => Self::NewMemberCommit,
        }
    }
}

impl TryFrom<WickrSender> for Sender {
    type Error = MlsTypesError;

    fn try_from(s: WickrSender) -> Result<Self, Self::Error> {
        match s {
            WickrSender::Member(m) => Ok(Self::Member(m)),
            WickrSender::External(e) => Ok(Self::External(e)),
            WickrSender::NewMemberProposal => Ok(Self::NewMemberProposal),
            WickrSender::NewMemberCommit => Ok(Self::NewMemberCommit),
            _ => Err(MlsTypesError::ImplementationError("Unsupported sender type")),
        }
    }
}
