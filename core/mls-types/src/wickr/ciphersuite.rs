use crate::{CipherSuite, MlsTypesError, mls_spec};

impl From<CipherSuite> for mls_rs::CipherSuite {
    fn from(v: CipherSuite) -> Self {
        match v {
            CipherSuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => Self::CURVE25519_AES128,
            CipherSuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => Self::P256_AES128,
            CipherSuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => Self::CURVE25519_CHACHA,
            CipherSuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448 => Self::CURVE448_AES256,
            CipherSuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521 => Self::P521_AES256,
            CipherSuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => Self::CURVE448_CHACHA,
            CipherSuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => Self::P384_AES256,
        }
    }
}

impl TryFrom<mls_rs::CipherSuite> for CipherSuite {
    type Error = MlsTypesError;

    fn try_from(v: mls_rs::CipherSuite) -> Result<Self, Self::Error> {
        match v {
            mls_rs::CipherSuite::CURVE25519_AES128 => Ok(Self::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519),
            mls_rs::CipherSuite::P256_AES128 => Ok(Self::MLS_128_DHKEMP256_AES128GCM_SHA256_P256),
            mls_rs::CipherSuite::CURVE25519_CHACHA => Ok(Self::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519),
            mls_rs::CipherSuite::CURVE448_AES256 => Ok(Self::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448),
            mls_rs::CipherSuite::P521_AES256 => Ok(Self::MLS_256_DHKEMP521_AES256GCM_SHA512_P521),
            mls_rs::CipherSuite::CURVE448_CHACHA => Ok(Self::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448),
            mls_rs::CipherSuite::P384_AES256 => Ok(Self::MLS_256_DHKEMP384_AES256GCM_SHA384_P384),
            _ => Err(MlsTypesError::WickrConversionError("Unknown ciphersuite")),
        }
    }
}

#[inline(always)]
pub fn mls_spec_to_mls_rs(value: mls_spec::defs::CiphersuiteId) -> mls_rs::CipherSuite {
    mls_rs::CipherSuite::from(*value)
}
