impl TryFrom<mls_rs::group::Member> for crate::Member {
    type Error = crate::MlsTypesError;

    fn try_from(m: mls_rs::group::Member) -> Result<Self, Self::Error> {
        let credential = m.signing_identity.credential.clone().try_into()?;
        let index = m.index.try_into()?;
        let extensions = m.extensions.clone().try_into()?;
        let capabilities = m.capabilities.try_into()?;
        Ok(Self::new(credential, index, extensions, capabilities))
    }
}
