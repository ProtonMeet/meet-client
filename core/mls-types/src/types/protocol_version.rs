#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize)]
#[repr(u16)]
pub enum ProtocolVersion {
    MLS10 = crate::mls_spec::defs::ProtocolVersion::Mls10 as u16,
    // only for testing config diffs
    #[cfg(any(test, feature = "test-utils"))]
    MLS11 = 0xFFFF,
}

impl ProtocolVersion {
    pub fn as_u16(&self) -> u16 {
        *self as u16
    }
}
