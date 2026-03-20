/// Used to initialize a MLS client Credential.
///
/// Some credential types, such as Basic can only carry a minimal assertion of
/// the user identity. Others, such as X509 or VC allow more identity components
/// to be sealed within the credential.
#[derive(Debug, Clone, PartialEq)]
pub enum DeviceIdentityArg<'a> {
    Basic,
    SdCwt { token: &'a identity::SdCwt },
}
