use crate::{IdentityError, IdentityResult, SdCwt, SdKbt, VerifiedSdCwt};
use ed25519_dalek::pkcs8::EncodePublicKey;
use meet_identifiers::{AsOwned, DeviceId, DeviceIdRef, Domain, ProtonEmail, UserId};
use proton_claims::reexports::coset;
use proton_claims::{
    About, CwtProtonLabel, Role as ProtonRole, UserAsserted,
    reexports::{SdCwtRead, SpiceOidcSdCwtRead, TokenQuery, spec::Value},
};
use url::Url;

pub trait ProtonMeetIdentity {
    fn sub(&mut self) -> IdentityResult<&str>;

    /// Issuance date of the CWT as UNIX timestamp in __seconds__
    fn cwt_iat(&mut self) -> IdentityResult<u64>;

    fn device_id(&mut self) -> IdentityResult<DeviceId> {
        Ok(self.sub()?.parse()?)
    }

    fn device_id_ref(&mut self) -> IdentityResult<DeviceIdRef<'_>> {
        Ok(self.sub()?.try_into()?)
    }

    fn user_id(&mut self) -> IdentityResult<UserId> {
        Ok(self.device_id()?.owning_identity_id().as_owned())
    }

    fn name(&mut self) -> IdentityResult<String>;

    fn handle(&mut self) -> IdentityResult<String>;

    fn email(&mut self) -> IdentityResult<ProtonEmail>;

    fn picture(&mut self) -> IdentityResult<Url>;

    fn workspace_role(&mut self) -> IdentityResult<ProtonRole>;

    fn domain(&mut self) -> IdentityResult<Domain> {
        Ok(self.user_id()?.domain().clone())
    }

    fn mls_identifier(&mut self) -> IdentityResult<Vec<u8>> {
        Ok(self.sub()?.as_bytes().to_vec())
    }

    fn holder_signature_public_key(&self) -> IdentityResult<Vec<u8>>;

    fn holder_signature_public_key_pem(&self) -> IdentityResult<String> {
        match self.alg() {
            coset::iana::Algorithm::EdDSA => {
                let raw_vk = self.holder_signature_public_key()?;
                let raw_vk = raw_vk
                    .as_slice()
                    .try_into()
                    .map_err(|_| IdentityError::ImplementationError("Invalid Ed25519 verifying key"))?;
                let vk = ed25519_dalek::VerifyingKey::from_bytes(raw_vk)?;
                Ok(vk.to_public_key_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)?)
            }
            _ => Err(IdentityError::ImplementationError("Unsupported alg")),
        }
    }

    fn alg(&self) -> coset::iana::Algorithm {
        // FIXME: assumes it's Ed25519 for now
        coset::iana::Algorithm::EdDSA
    }
}

impl ProtonMeetIdentity for SdCwt {
    fn sub(&mut self) -> IdentityResult<&str> {
        SdCwtRead::sub(self)?.ok_or_else(|| IdentityError::MissingClaim("sub".into()))
    }

    fn cwt_iat(&mut self) -> IdentityResult<u64> {
        Ok(SdCwtRead::iat(self)?.ok_or_else(|| IdentityError::MissingClaim("iat".into()))? as u64)
    }

    fn name(&mut self) -> IdentityResult<String> {
        Ok(SpiceOidcSdCwtRead::name(self)?
            .ok_or_else(|| IdentityError::MissingClaim("name".into()))?
            .to_string())
    }

    fn handle(&mut self) -> IdentityResult<String> {
        Ok(SpiceOidcSdCwtRead::preferred_username(self)?
            .ok_or_else(|| IdentityError::MissingClaim("preferred_username".into()))?
            .to_string())
    }

    fn email(&mut self) -> IdentityResult<ProtonEmail> {
        let email = SpiceOidcSdCwtRead::email(self)?
            .ok_or_else(|| IdentityError::MissingClaim("email".into()))?
            .to_string();
        Ok(ProtonEmail::new_unchecked(email))
    }

    fn picture(&mut self) -> IdentityResult<Url> {
        SpiceOidcSdCwtRead::picture(self)?.ok_or_else(|| IdentityError::MissingClaim("picture".into()))
    }

    fn workspace_role(&mut self) -> IdentityResult<ProtonRole> {
        Ok(self
            .query(vec![(CwtProtonLabel::Role as i64).into()].into())?
            .map(|v| v.deserialized::<ProtonRole>())
            .transpose()?
            .map(Into::into)
            .unwrap_or_default())
    }

    fn holder_signature_public_key(&self) -> IdentityResult<Vec<u8>> {
        let cnf = self.0.payload.clone_value()?.cnf;
        let pk = ed25519_dalek::VerifyingKey::try_from(&cnf)
            .map_err(|_| IdentityError::ImplementationError("Invalid Ed25519 key"))?;
        Ok(pk.as_bytes().to_vec())
    }
}

impl ProtonMeetIdentity for VerifiedSdCwt {
    fn sub(&mut self) -> IdentityResult<&str> {
        ProtonMeetIdentity::sub(&mut self.0)
    }

    fn cwt_iat(&mut self) -> IdentityResult<u64> {
        ProtonMeetIdentity::cwt_iat(&mut self.0)
    }

    fn name(&mut self) -> IdentityResult<String> {
        ProtonMeetIdentity::name(&mut self.0)
    }

    fn handle(&mut self) -> IdentityResult<String> {
        ProtonMeetIdentity::handle(&mut self.0)
    }

    fn email(&mut self) -> IdentityResult<ProtonEmail> {
        ProtonMeetIdentity::email(&mut self.0)
    }

    fn picture(&mut self) -> IdentityResult<Url> {
        ProtonMeetIdentity::picture(&mut self.0)
    }

    fn workspace_role(&mut self) -> IdentityResult<ProtonRole> {
        ProtonMeetIdentity::workspace_role(&mut self.0)
    }

    fn holder_signature_public_key(&self) -> IdentityResult<Vec<u8>> {
        let cnf = self.0.0.payload.clone_value()?.cnf;
        let pk = ed25519_dalek::VerifyingKey::try_from(&cnf)
            .map_err(|_| IdentityError::ImplementationError("Invalid Ed25519 key"))?;
        Ok(pk.as_bytes().to_vec())
    }
}

impl ProtonMeetIdentity for SdKbt {
    fn sub(&mut self) -> IdentityResult<&str> {
        SdCwtRead::sub(self)?.ok_or_else(|| IdentityError::MissingClaim("sub".into()))
    }

    fn cwt_iat(&mut self) -> IdentityResult<u64> {
        Ok(SdCwtRead::iat(self)?.ok_or_else(|| IdentityError::MissingClaim("iat".into()))? as u64)
    }

    fn name(&mut self) -> IdentityResult<String> {
        Ok(SpiceOidcSdCwtRead::name(self)?
            .ok_or_else(|| IdentityError::MissingClaim("name".into()))?
            .to_string())
    }

    fn handle(&mut self) -> IdentityResult<String> {
        Ok(SpiceOidcSdCwtRead::preferred_username(self)?
            .ok_or_else(|| IdentityError::MissingClaim("preferred_username".into()))?
            .to_string())
    }

    fn email(&mut self) -> IdentityResult<ProtonEmail> {
        let email = SpiceOidcSdCwtRead::email(self)?
            .ok_or_else(|| IdentityError::MissingClaim("email".into()))?
            .to_string();
        Ok(ProtonEmail::new_unchecked(email))
    }

    fn picture(&mut self) -> IdentityResult<Url> {
        SpiceOidcSdCwtRead::picture(self)?.ok_or_else(|| IdentityError::MissingClaim("picture".into()))
    }

    fn workspace_role(&mut self) -> IdentityResult<ProtonRole> {
        Ok(self
            .query(vec![(CwtProtonLabel::Role as i64).into()].into())?
            .map(|v| Value::deserialized::<ProtonRole>(&v))
            .transpose()?
            .map(Into::into)
            // if the role is not present, we default to the "user" role
            .unwrap_or_default())
    }

    fn holder_signature_public_key(&self) -> IdentityResult<Vec<u8>> {
        let sd_cwt = self.0.protected.clone_value()?.kcwt.clone_value()?;
        let cnf = sd_cwt.0.payload.clone_value()?.cnf;
        let pk = ed25519_dalek::VerifyingKey::try_from(&cnf)
            .map_err(|_| IdentityError::ImplementationError("Invalid Ed25519 key"))?;
        Ok(pk.as_bytes().to_vec())
    }
}

pub trait ProtonMeetUserAssertedIdentity {
    fn user_asserted(&mut self) -> IdentityResult<Option<&UserAsserted>>;

    /// IMPORTANT: this is the 'iat' claim of the SD-KBT, not the one of the SD-CWT !
    ///
    /// Issuance date of the KBT as UNIX timestamp in __seconds__
    fn kbt_iat(&mut self) -> IdentityResult<u64>;

    fn about(&mut self) -> IdentityResult<Option<&About>> {
        Ok(self.user_asserted()?.and_then(|u| u.about.as_ref()))
    }
}

impl ProtonMeetUserAssertedIdentity for SdKbt {
    fn user_asserted(&mut self) -> IdentityResult<Option<&UserAsserted>> {
        Ok(self.0.payload.to_value()?.extra.as_ref())
    }

    fn kbt_iat(&mut self) -> IdentityResult<u64> {
        Ok(self.0.iat()?)
    }
}
