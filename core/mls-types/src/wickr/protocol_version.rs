use crate::{MlsTypesError, ProtocolVersion};

impl From<ProtocolVersion> for mls_rs::ProtocolVersion {
    fn from(v: ProtocolVersion) -> Self {
        match v {
            ProtocolVersion::MLS10 => Self::new(1),
            #[cfg(any(test, feature = "test-utils"))]
            ProtocolVersion::MLS11 => Self::new(0xFFFF),
        }
    }
}

impl TryFrom<mls_rs::ProtocolVersion> for ProtocolVersion {
    type Error = MlsTypesError;

    fn try_from(v: mls_rs::ProtocolVersion) -> Result<Self, Self::Error> {
        match u16::from(v) {
            1 => Ok(Self::MLS10),
            #[cfg(any(test, feature = "test-utils"))]
            0xFFFF => Ok(Self::MLS11),
            _ => Err(MlsTypesError::WickrConversionError("Unknown protocol version")),
        }
    }
}

#[inline(always)]
pub fn mls_spec_to_mls_rs(value: crate::mls_spec::defs::ProtocolVersion) -> mls_rs::ProtocolVersion {
    mls_rs::ProtocolVersion::from(value as u16)
}
