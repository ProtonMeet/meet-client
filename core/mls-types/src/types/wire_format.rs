use crate::mls_spec;

#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
#[repr(u16)]
/// Wire format
/// See https://www.rfc-editor.org/rfc/rfc9420.html#name-mls-wire-formats
pub enum WireFormat {
    /// PublicMessage
    /// see https://www.rfc-editor.org/rfc/rfc9420.html#section-6.2-2
    PublicMessage = mls_spec::defs::WireFormat::MLS_PUBLIC_MESSAGE,

    /// PrivateMessage
    /// see https://www.rfc-editor.org/rfc/rfc9420.html#section-6.3-2
    PrivateMessage = mls_spec::defs::WireFormat::MLS_PRIVATE_MESSAGE,

    /// Welcome
    /// see https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.3.1-5
    Welcome = mls_spec::defs::WireFormat::MLS_WELCOME,

    /// GroupInfo
    /// see https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.3-2
    GroupInfo = mls_spec::defs::WireFormat::MLS_GROUP_INFO,

    /// KeyPackage
    /// see https://www.rfc-editor.org/rfc/rfc9420.html#section-10-6
    KeyPackage = mls_spec::defs::WireFormat::MLS_KEY_PACKAGE,

    // TargetedMessage = mls_spec::drafts::mls_extensions::WIRE_FORMAT_MLS_TARGETED_MESSAGE,
    SemiPrivateMessage = mls_spec::drafts::semiprivate_message::WIRE_FORMAT_MLS_SEMIPRIVATE_MESSAGE,
}

impl std::fmt::Display for WireFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::PublicMessage => "PublicMessage",
            Self::PrivateMessage => "PrivateMessage",
            Self::Welcome => "Welcome",
            Self::GroupInfo => "GroupInfo",
            Self::KeyPackage => "KeyPackage",
            // Self::TargetedMessage => "TargetedMessage",
            Self::SemiPrivateMessage => "SemiPrivateMessage",
        };
        write!(f, "{name}")
    }
}
