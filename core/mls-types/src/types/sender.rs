use crate::mls_spec;
use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};

const SNDR_MEMBER: u8 = mls_spec::messages::SenderType::Member as u8;
const SNDR_EXTERNAL: u8 = mls_spec::messages::SenderType::External as u8;
const SNDR_NEWMEMBERPROPOSAL: u8 = mls_spec::messages::SenderType::NewMemberProposal as u8;
const SNDR_NEWMEMBERCOMMIT: u8 = mls_spec::messages::SenderType::NewMemberCommit as u8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode)]
#[repr(u8)]
pub enum Sender {
    Member(u32) = SNDR_MEMBER,
    External(u32) = SNDR_EXTERNAL,
    NewMemberProposal = SNDR_NEWMEMBERPROPOSAL,
    NewMemberCommit = SNDR_NEWMEMBERCOMMIT,
}
