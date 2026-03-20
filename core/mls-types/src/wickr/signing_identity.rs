use crate::{MlsTypesError, SigningIdentity};

impl TryFrom<mls_rs::identity::SigningIdentity> for SigningIdentity {
    type Error = MlsTypesError;

    fn try_from(value: mls_rs::identity::SigningIdentity) -> Result<Self, Self::Error> {
        Ok(Self {
            signature_key: value.signature_key.into(),
            credential: value.credential.try_into()?,
        })
    }
}

impl TryFrom<SigningIdentity> for mls_rs::identity::SigningIdentity {
    type Error = MlsTypesError;

    fn try_from(value: SigningIdentity) -> Result<Self, Self::Error> {
        Ok(Self {
            signature_key: value.signature_key.into(),
            credential: value.credential.try_into()?,
        })
    }
}
