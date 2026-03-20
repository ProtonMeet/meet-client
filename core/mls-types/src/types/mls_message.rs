use crate::mls_spec;
use meet_identifiers::{GroupId, UserId};
use mls_rs::{
    framing::{Content, MlsMessagePayload},
    group::proposal::ProposalOrRef,
};
use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};

use crate::{
    CipherSuite, Credential, GroupInfo, GroupInfoRef, MlsTypesError, MlsTypesResult, Proposal, ProtocolVersion, Sender,
    Welcome,
    types::{content_type::ContentType, key_package::KeyPackage, wire_format::WireFormat},
};

use super::welcome::WelcomeRef;

#[derive(Clone, Debug, MlsDecode, MlsEncode, MlsSize)]
pub struct MlsMessage {
    pub mls_message: Box<mls_rs::MlsMessage>,
    /// A "virtual" time at which to perform validations, in order
    /// to be able to support things like KeyPackages or Credentials that
    /// are expired as of "now" but were still valid at the time the Commits
    /// or Proposals were made.
    pub(crate) virtual_time: Option<u64>,
}

impl TryFrom<mls_spec::messages::MlsMessage> for MlsMessage {
    type Error = MlsTypesError;

    fn try_from(value: mls_spec::messages::MlsMessage) -> Result<Self, Self::Error> {
        use crate::mls_spec::Serializable as _;
        let tls_bytes = value.to_tls_bytes()?;
        Ok(Self {
            mls_message: Box::new(mls_rs::MlsMessage::mls_decode(&mut &tls_bytes[..])?),
            virtual_time: None,
        })
    }
}

impl TryFrom<MlsMessage> for mls_spec::messages::MlsMessage {
    type Error = MlsTypesError;

    fn try_from(value: MlsMessage) -> Result<Self, Self::Error> {
        use crate::mls_spec::Parsable as _;
        let tls_bytes = value.mls_message.mls_encode_to_vec()?;
        Ok(Self::from_tls_bytes(&tls_bytes)?)
    }
}

impl MlsMessage {
    pub fn virtual_time(&self) -> Option<u64> {
        self.virtual_time
    }

    pub fn with_virtual_time(mut self, time: u64) -> Self {
        self.virtual_time.replace(time);
        self
    }

    pub fn version(&self) -> MlsTypesResult<ProtocolVersion> {
        self.mls_message.version.try_into()
    }

    pub fn wire_format(&self) -> MlsTypesResult<WireFormat> {
        self.mls_message.wire_format().try_into()
    }

    pub fn group_id(&self) -> MlsTypesResult<GroupId> {
        Ok(GroupId::try_from(self.mls_message.group_id().ok_or(
            MlsTypesError::ImplementationError("Tried to access a group id without checking the message type"),
        )?)?)
    }

    pub fn epoch(&self) -> Option<u64> {
        self.mls_message.epoch()
    }

    pub fn key_package_credential(&self) -> MlsTypesResult<Credential> {
        let kp = self
            .mls_message
            .as_key_package()
            .ok_or(MlsTypesError::ImplementationError("Not a KeyPackage"))?;
        let credential = kp.leaf_node.signing_identity.credential.clone().try_into()?;
        Ok(credential)
    }

    pub fn key_package_user_id(&mut self) -> MlsTypesResult<UserId> {
        self.key_package_credential()?.user_id()
    }

    pub fn into_welcome(self) -> Option<Welcome> {
        self.mls_message.into_welcome().map(Into::into)
    }

    pub fn as_welcome(&self) -> Option<WelcomeRef<'_>> {
        self.mls_message.as_welcome().map(Into::into)
    }

    pub fn confirmation_tag(&self) -> Option<&[u8]> {
        self.mls_message
            .as_plaintext()
            .and_then(|p| p.auth.confirmation_tag.as_deref())
            .map(Vec::as_slice)
    }

    pub fn as_proposal(&self) -> Option<&mls_rs::group::proposal::Proposal> {
        self.mls_message.as_plaintext().and_then(|p| match &p.content.content {
            Content::Proposal(p) => Some(p.as_ref()),
            _ => None,
        })
    }

    pub fn welcome_ciphersuite(&self) -> MlsTypesResult<Option<CipherSuite>> {
        self.mls_message
            .as_welcome()
            .map(|w| w.cipher_suite)
            .map(TryInto::try_into)
            .transpose()
    }

    pub fn into_key_package(self) -> Option<KeyPackage> {
        self.mls_message.into_key_package().map(|k| KeyPackage(Box::new(k)))
    }

    pub fn into_group_info(self) -> Option<GroupInfo> {
        self.mls_message.into_group_info().map(Into::into)
    }

    pub fn as_group_info(&self) -> Option<GroupInfoRef<'_>> {
        self.mls_message.as_group_info().map(Into::into)
    }

    pub fn from_bytes(bytes: &[u8]) -> MlsTypesResult<Self> {
        Ok(mls_rs::MlsMessage::from_bytes(bytes).map(|m| Self {
            mls_message: Box::new(m),
            virtual_time: None,
        })?)
    }

    pub fn content_type(&self) -> MlsTypesResult<ContentType> {
        let ct = match &self.mls_message.payload {
            MlsMessagePayload::Plain(m) => m.content.content_type(),
            MlsMessagePayload::Cipher(m) => m.content_type,
            _ => {
                return Err(MlsTypesError::ImplementationError(
                    "Called 'content_type' not on a Public|Private Message",
                ));
            }
        };
        Ok(ct.into())
    }

    pub fn sender(&self) -> MlsTypesResult<Sender> {
        match &self.mls_message.payload {
            MlsMessagePayload::Plain(m) => Ok(m.content.sender.try_into()?),
            _ => Err(MlsTypesError::ImplementationError(
                "Tried to get sender on an unsupported message type",
            )),
        }
    }

    pub fn as_inner(&self) -> &mls_rs::MlsMessage {
        &self.mls_message
    }

    pub fn proposals_by_value(&self) -> Option<impl Iterator<Item = Proposal> + use<'_>> {
        match &self.mls_message.payload {
            MlsMessagePayload::Plain(mls_rs::framing::PublicMessage {
                content:
                    mls_rs::framing::FramedContent {
                        content: Content::Commit(commit),
                        ..
                    },
                ..
            }) => Some(commit.as_ref().proposals.iter().filter_map(|p| match p {
                ProposalOrRef::Proposal(p) => Some(p.as_ref().clone().try_into().ok()?),
                _ => None,
            })),
            _ => None,
        }
    }

    pub fn sender_credential(&self) -> MlsTypesResult<Option<Credential>> {
        match &self.mls_message.payload {
            MlsMessagePayload::Plain(mls_rs::framing::PublicMessage {
                content:
                    mls_rs::framing::FramedContent {
                        content: Content::Commit(commit),
                        ..
                    },
                ..
            }) => {
                let Some(path) = &commit.as_ref().path else {
                    return Ok(None);
                };
                let credential = path.leaf_node.signing_identity.credential.clone();
                Ok(Some(credential.try_into()?))
            }
            _ => Ok(None),
        }
    }
}
