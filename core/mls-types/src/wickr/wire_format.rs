use crate::{MlsTypesError, types::wire_format::WireFormat};

impl TryFrom<WireFormat> for mls_rs::WireFormat {
    type Error = MlsTypesError;

    fn try_from(v: WireFormat) -> Result<Self, Self::Error> {
        Ok(match v {
            WireFormat::PublicMessage => Self::PublicMessage,
            WireFormat::PrivateMessage => Self::PrivateMessage,
            WireFormat::Welcome => Self::Welcome,
            WireFormat::GroupInfo => Self::GroupInfo,
            WireFormat::KeyPackage => Self::KeyPackage,
            WireFormat::SemiPrivateMessage /*| WireFormat::TargetedMessage*/ => {
                return Err(MlsTypesError::ImplementationError("WireFormat not supported by mls-rs"));
            }
        })
    }
}

impl TryFrom<mls_rs::WireFormat> for WireFormat {
    type Error = MlsTypesError;

    fn try_from(v: mls_rs::WireFormat) -> Result<Self, Self::Error> {
        match v {
            mls_rs::WireFormat::PublicMessage => Ok(Self::PublicMessage),
            mls_rs::WireFormat::PrivateMessage => Ok(Self::PrivateMessage),
            mls_rs::WireFormat::Welcome => Ok(Self::Welcome),
            mls_rs::WireFormat::GroupInfo => Ok(Self::GroupInfo),
            mls_rs::WireFormat::KeyPackage => Ok(Self::KeyPackage),
            _ => Err(MlsTypesError::WickrConversionError("Unknown wire format")),
        }
    }
}
