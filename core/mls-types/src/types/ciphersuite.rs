use crate::{MlsTypesError, mls_spec, mls_spec::defs::CiphersuiteId};

/// MLS Ciphersuite
/// See https://www.rfc-editor.org/rfc/rfc9420.html#name-mls-cipher-suites
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
#[repr(u16)]
pub enum CipherSuite {
    /// DH KEM x25519 | AES-GCM 128 | SHA2-256 | Ed25519
    MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 =
        mls_spec::defs::CiphersuiteId::MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519,
    /// DH KEM P256 | AES-GCM 128 | SHA2-256 | EcDSA P256
    MLS_128_DHKEMP256_AES128GCM_SHA256_P256 = mls_spec::defs::CiphersuiteId::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
    /// DH KEM x25519 | Chacha20Poly1305 | SHA2-256 | Ed25519
    MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 =
        mls_spec::defs::CiphersuiteId::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519,
    /// DH KEM x448 | AES-GCM 256 | SHA2-512 | Ed448
    MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448 = mls_spec::defs::CiphersuiteId::MLS_256_DHKEMX448_AES256GCM_SHA512_ED448,
    /// DH KEM P521 | AES-GCM 256 | SHA2-512 | EcDSA P521
    MLS_256_DHKEMP521_AES256GCM_SHA512_P521 = mls_spec::defs::CiphersuiteId::MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
    /// DH KEM x448 | Chacha20Poly1305 | SHA2-512 | Ed448
    MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 =
        mls_spec::defs::CiphersuiteId::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_ED448,
    /// DH KEM P384 | AES-GCM 256 | SHA2-384 | EcDSA P384
    MLS_256_DHKEMP384_AES256GCM_SHA384_P384 = mls_spec::defs::CiphersuiteId::MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
}

impl std::fmt::Display for CipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            Self::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => "MLS_128_DHKEMP256_AES128GCM_SHA256_P256",
            Self::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
                "MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519"
            }
            Self::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448 => "MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448",
            Self::MLS_256_DHKEMP521_AES256GCM_SHA512_P521 => "MLS_256_DHKEMP521_AES256GCM_SHA512_P521",
            Self::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => "MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448",
            Self::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => "MLS_256_DHKEMP384_AES256GCM_SHA384_P384",
        };
        write!(f, "{name}")
    }
}

impl TryFrom<u16> for CipherSuite {
    type Error = MlsTypesError;

    fn try_from(v: u16) -> Result<Self, Self::Error> {
        Ok(match v {
            CiphersuiteId::MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519 => {
                Self::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            }
            CiphersuiteId::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => Self::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
            CiphersuiteId::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519 => {
                Self::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            }
            CiphersuiteId::MLS_256_DHKEMX448_AES256GCM_SHA512_ED448 => Self::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,
            CiphersuiteId::MLS_256_DHKEMP521_AES256GCM_SHA512_P521 => Self::MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
            CiphersuiteId::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_ED448 => {
                Self::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448
            }
            CiphersuiteId::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => Self::MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
            _ => return Err(MlsTypesError::ImplementationError("Unknown Ciphersuite")),
        })
    }
}

impl TryFrom<CiphersuiteId> for CipherSuite {
    type Error = MlsTypesError;

    fn try_from(cs: CiphersuiteId) -> Result<Self, Self::Error> {
        (*cs).try_into()
    }
}

impl TryFrom<CipherSuite> for CiphersuiteId {
    type Error = MlsTypesError;

    fn try_from(cs: CipherSuite) -> Result<Self, Self::Error> {
        (cs as u16).try_into().map_err(MlsTypesError::MlsSpecError)
    }
}

#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
#[repr(u16)]
pub enum SignatureAlgorithm {
    #[default]
    Ed25519,
    Ed448,
    P256,
    P384,
    P521,
}

#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
#[repr(u16)]
pub enum HashAlgorithm {
    #[default]
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    /// Returns the hash algorithm [IANA] id as a u8
    ///
    /// [IANA]: https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg
    #[inline]
    pub const fn id(self) -> u8 {
        match self {
            Self::Sha256 => 1,
            Self::Sha384 => 7,
            Self::Sha512 => 8,
        }
    }

    pub fn kdf_extract_size(&self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

impl TryFrom<u8> for HashAlgorithm {
    type Error = MlsTypesError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Sha256),
            7 => Ok(Self::Sha384),
            8 => Ok(Self::Sha512),
            v => Err(MlsTypesError::InvalidHashAlgorithm(v)),
        }
    }
}

impl CipherSuite {
    pub fn hash_alg(&self) -> HashAlgorithm {
        match self {
            Self::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Self::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | Self::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => HashAlgorithm::Sha256,
            Self::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | Self::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448
            | Self::MLS_256_DHKEMP521_AES256GCM_SHA512_P521 => HashAlgorithm::Sha512,
            Self::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => HashAlgorithm::Sha384,
        }
    }

    pub fn signature_alg(&self) -> SignatureAlgorithm {
        match self {
            Self::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Self::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => SignatureAlgorithm::Ed25519,
            Self::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448 | Self::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
                SignatureAlgorithm::Ed448
            }
            Self::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => SignatureAlgorithm::P256,
            Self::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => SignatureAlgorithm::P384,
            Self::MLS_256_DHKEMP521_AES256GCM_SHA512_P521 => SignatureAlgorithm::P521,
        }
    }

    pub fn kdf_extract_size(&self) -> usize {
        self.hash_alg().kdf_extract_size()
    }
}

