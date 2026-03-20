use crate::error::SuccessorError;
use crate::mimi_protocol_mls::{UserIdentifier, reexports::mls_spec};
use crate::mimi_room_policy::policy::ClaimExtractor;
use crate::{MlsClientConfig, MlsError};
use base64::Engine;
use identity::{ProtonEd25519SdCwtVerifier, ProtonMeetIdentity, SD_CWT_LEEWAY, SD_KBT_LEEWAY, SdKbt};
use meet_identifiers::{AsOwned, DeviceId, UserId, UserIdRef};
use mls_rs::{
    ExtensionList, IdentityProvider,
    identity::{Credential, CredentialType, CustomCredential, SigningIdentity},
    time::MlsTime,
};
use mls_rs_core::identity::MemberValidationContext;
use mls_spec::drafts::sd_cwt_credential::CREDENTIAL_SD_CWT;
use mls_types::{CipherSuite, CredentialExt};
use proton_claims::{
    Role,
    reexports::{
        CwtAny, CwtTimeError, Query, SdCwtRead, SdCwtVerifierError, TimeVerification, TokenQuery, Verifier,
        VerifierParams, cose_key_set::CoseKeySet,
    },
};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct ProtonMeetIdentityProvider {
    pub auth_cks: Arc<CoseKeySet>,
    pub server_cks: Arc<CoseKeySet>,
    pub config: Arc<MlsClientConfig>,
    #[cfg(feature = "test-utils")]
    pub identity_tester: Option<IdentityTester>,
}

#[maybe_async::must_be_async]
impl IdentityProvider for ProtonMeetIdentityProvider {
    type Error = MlsError;

    async fn validate_member(
        &self,
        signing_identity: &SigningIdentity,
        timestamp: Option<MlsTime>,
        context: MemberValidationContext<'_>,
    ) -> Result<(), Self::Error> {
        #[cfg(feature = "test-utils")]
        if let Some(s) = self.identity_tester.as_ref().and_then(|s| s.validate_member) {
            return s(self, signing_identity, timestamp, context);
        }

        match &signing_identity.credential {
            #[cfg(any(test, feature = "test-utils"))]
            Credential::Basic(_) => Ok(()),
            Credential::Custom(CustomCredential {
                credential_type,
                data: sd_kbt,
            }) if *credential_type == mls_spec::defs::CredentialType::SD_CWT_CREDENTIAL.into() => {
                // TODO: params from context

                // 'timestamp' is only present at sending time because we do not want to validate
                // it at reception time because the source of truth for that would be the DS which we do not trust
                // let artificial_time = timestamp.map(|_| MlsTime::now().seconds_since_epoch() as i64);
                // That's great and all but if you have expiration < message_retention_period on the server, you
                // cannot validate caught up commits that add/update credentials because if, say, expiration is 3 days,
                // catching up after 3 days would cause credential validation to fail because you're validating those credentials at
                // "now" and obviously those credentials aren't valid anymore. Instead you should trust the server a tad more
                // and perform the validations at the time the commit was seen by the server to put things back in context
                let artificial_time = timestamp.map(|t| t.seconds_since_epoch() as i64);

                // except for new group creation or joining a group via Welcome, we should validate members time claims
                let verify_exp = !matches!(context, MemberValidationContext::ForNewGroup { .. });

                let time_verification = TimeVerification {
                    verify_exp,
                    verify_iat: false, // don't care and not set for privacy reasons
                    verify_nbf: false, // same
                };

                // signature public key to verify the SD-CWT & SD-KBT against
                let verifier = match &context {
                    MemberValidationContext::ForCommit { current_context, .. }
                    | MemberValidationContext::ForNewGroup { current_context } => {
                        let cs: CipherSuite = current_context.cipher_suite.try_into()?;
                        match cs {
                            CipherSuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
                            | CipherSuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
                                let vk = signing_identity.signature_key.as_bytes();
                                let vk = vk.try_into()?;
                                let vk = ed25519_dalek::VerifyingKey::from_bytes(vk)?;
                                Some(Box::new(vk))
                            }
                            _ => return Err(MlsError::ImplementationError("Ciphersuite not yet supported")),
                        }
                    }
                    _ => None,
                };

                let params = VerifierParams {
                    sd_kbt_leeway: SD_KBT_LEEWAY,
                    sd_cwt_leeway: SD_CWT_LEEWAY,
                    artificial_time,
                    sd_kbt_time_verification: time_verification,
                    sd_cwt_time_verification: time_verification,
                    ..Default::default()
                };

                let sd_kbt =
                    match ProtonEd25519SdCwtVerifier.verify_sd_kbt(sd_kbt, params, verifier.as_deref(), &self.auth_cks)
                    {
                        Ok(sd_kbt) => sd_kbt,
                        Err(SdCwtVerifierError::TimeError(CwtTimeError::Expired)) => {
                            let token = SdKbt::from_cbor_bytes(sd_kbt);
                            let identity = token.map(|mut t| t.mls_identifier());
                            tracing::error!(
                                "member sd_kbt verification failed for {identity:?} with verifying key {:?}, token={}",
                                self.server_cks,
                                base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(sd_kbt)
                            );
                            return Err(MlsError::NewMemberExpired);
                        }
                        Err(SdCwtVerifierError::TimeError(CwtTimeError::NotValidYet)) => {
                            return Err(MlsError::NewMemberNotYetValid);
                        }
                        Err(e) => return Err(e.into()),
                    };

                if sd_kbt.claimset.map(|c| c.role == Role::ProtonAdmin).unwrap_or_default() {
                    tracing::warn!("Issuer key compromised and credential issued with invalid role");
                    return Err(Self::Error::InvalidMember);
                }
                Ok(())
            }
            _ => Err(MlsError::ImplementationError(
                "Credential validation not yet supported for this type",
            )),
        }
    }

    /// Make sure the external sender was issued by a known signer
    async fn validate_external_sender(
        &self,
        signing_identity: &SigningIdentity,
        timestamp: Option<MlsTime>,
        _extensions: Option<&ExtensionList>,
    ) -> Result<(), Self::Error> {
        let Some(raw_sd_kbt) = signing_identity.credential.as_sd_cwt() else {
            return Err(Self::Error::ImplementationError(
                "Unsupported external sender credential type",
            ));
        };

        let artificial_time = timestamp.map(|t| t.seconds_since_epoch() as i64);

        let params = VerifierParams {
            expected_subject: None,
            expected_issuer: None,
            expected_audience: None,
            expected_kbt_audience: None,
            expected_cnonce: None,
            sd_cwt_leeway: SD_CWT_LEEWAY,
            sd_kbt_leeway: SD_KBT_LEEWAY,
            sd_cwt_time_verification: TimeVerification {
                verify_exp: true,
                verify_iat: false, // FIXME: after introducing a leeway in iat
                verify_nbf: true,
            },
            sd_kbt_time_verification: TimeVerification {
                verify_exp: true,
                verify_iat: false, // FIXME: after introducing a leeway in iat
                verify_nbf: true,
            },
            artificial_time,
        };

        let sd_kbt = ProtonEd25519SdCwtVerifier.verify_sd_kbt(raw_sd_kbt, params, None, self.server_cks.as_ref())
            .inspect_err(|e| {
                let token = SdKbt::from_cbor_bytes(raw_sd_kbt);
                let identity = token.map(|mut t| t.mls_identifier());
                tracing::error!("external_sender sd_kbt verification failed for {identity:?} with verifying key {:?}: error={e:?}, token={}", self.server_cks,
                base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(raw_sd_kbt));
            })?;

        if sd_kbt.claimset.map(|c| c.role != Role::ProtonAdmin).unwrap_or(true) {
            return Err(Self::Error::InvalidExternalSender);
        }

        Ok(())
    }

    async fn identity(
        &self,
        signing_identity: &SigningIdentity,
        _extensions: &ExtensionList,
    ) -> Result<Vec<u8>, Self::Error> {
        // this returns the device id
        Ok(match &signing_identity.credential {
            #[cfg(any(test, feature = "test-utils"))]
            Credential::Basic(c) => c.identifier.clone(),
            Credential::Custom(CustomCredential {
                credential_type,
                data: sd_kbt,
            }) if *credential_type == mls_spec::defs::CredentialType::SD_CWT_CREDENTIAL.into() => {
                if let Ok(mut token) = SdKbt::from_cbor_bytes(sd_kbt) {
                    token
                        .mls_identifier()
                        .map_err(|_e| MlsError::ImplementationError("SD-CWT lacks MLS identity"))?
                } else {
                    return Err(MlsError::ImplementationError("Cannot deserialize SD-CWT"));
                }
            }
            _ => unimplemented!(),
        })
    }

    async fn valid_successor(
        &self,
        predecessor: &SigningIdentity,
        successor: &SigningIdentity,
        _extensions: &ExtensionList,
    ) -> Result<bool, Self::Error> {
        #[cfg(feature = "test-utils")]
        if let Some(s) = self.identity_tester.as_ref().and_then(|s| s.validate_successor) {
            return s(self, predecessor, successor, _extensions);
        }

        if predecessor.signature_key != successor.signature_key {
            return Err(Self::Error::SignatureKeyChanged);
        }

        let mut predecessor = predecessor
            .credential
            .as_sd_cwt()
            .map(SdKbt::from_cbor_bytes)
            .transpose()?
            .ok_or(MlsError::UnsupportedCredentialType)?;

        let raw_successor = successor
            .credential
            .as_sd_cwt()
            .ok_or(MlsError::UnsupportedCredentialType)?;
        let mut successor = SdKbt::from_cbor_bytes(raw_successor)?;

        let predecessor_sub = SdCwtRead::sub(&mut predecessor)?
            .ok_or(MlsError::UnidentifiableCredential)?
            .to_string();
        let successor_sub = SdCwtRead::sub(&mut successor)?.ok_or(MlsError::UnidentifiableCredential)?;
        if predecessor_sub != successor_sub {
            return Err(SuccessorError::DifferentSub.into());
        }
        let predecessor_cnf = &predecessor.0.sd_cwt_payload()?.cnf;
        let successor_cnf = &successor.0.sd_cwt_payload()?.cnf;

        if predecessor_cnf != successor_cnf {
            return Err(SuccessorError::DifferentConfirmationKey.into());
        }

        // FIXME: very pedantic verification and seems not ready yet
        // let room_id = extensions.room_id()?.map(|i| i.to_string());

        // verify the successor
        let params = VerifierParams {
            expected_subject: Some(predecessor_sub.as_ref()),
            expected_issuer: None, // no compelling reason to enforce this
            expected_audience: None,
            // expected_kbt_audience: room_id.as_deref(), // in case a room id is defined verified the SD-KBT uses it as an audience
            expected_kbt_audience: None, // in case a room id is defined verified the SD-KBT uses it as an audience
            expected_cnonce: None,
            sd_cwt_leeway: SD_CWT_LEEWAY,
            sd_kbt_leeway: SD_KBT_LEEWAY,
            // we've got to be lenient here as we might be decrypting a commit which was valid once
            // created but has expired meanwhile
            sd_cwt_time_verification: TimeVerification {
                verify_exp: false,
                verify_iat: false,
                verify_nbf: false,
            },
            sd_kbt_time_verification: TimeVerification {
                verify_exp: false,
                verify_iat: false,
                verify_nbf: false,
            },
            artificial_time: None,
        };
        ProtonEd25519SdCwtVerifier.verify_sd_kbt(raw_successor, params, None, self.auth_cks.as_ref())?;

        Ok(true)
    }

    fn supported_types(&self) -> Vec<CredentialType> {
        self.config.supported_credential_types()
    }
}

impl ProtonMeetIdentityProvider {
    pub fn new(auth_cks: &CoseKeySet, server_cks: &CoseKeySet, config: MlsClientConfig) -> Self {
        Self {
            auth_cks: Arc::new(auth_cks.clone()),
            server_cks: Arc::new(server_cks.clone()),
            config: Arc::new(config),
            #[cfg(feature = "test-utils")]
            identity_tester: None,
        }
    }

    pub fn identity_from_credential(
        credential: &mut mls_types::Credential,
        _extensions: &ExtensionList,
    ) -> Result<UserIdentifier, MlsError> {
        Ok(Self::user_identifier(&credential.user_id()?))
    }

    pub fn identity_from_signing_identity(signing_identity: &SigningIdentity) -> Result<UserIdentifier, MlsError> {
        let device_id = match &signing_identity.credential {
            #[cfg(any(test, feature = "test-utils"))]
            Credential::Basic(c) => c.identifier.clone(),
            Credential::Custom(CustomCredential {
                credential_type,
                data: sd_kbt,
            }) if *credential_type == mls_spec::defs::CredentialType::SD_CWT_CREDENTIAL.into() => {
                if let Ok(mut token) = SdKbt::from_cbor_bytes(sd_kbt) {
                    token
                        .mls_identifier()
                        .map_err(|_e| MlsError::ImplementationError("SD-CWT lacks MLS identity"))?
                } else {
                    return Err(MlsError::ImplementationError("Cannot deserialize SD-CWT"));
                }
            }
            _ => unimplemented!(),
        };

        let device_id = DeviceId::try_from(&device_id[..])?;
        let user_id = device_id.owning_identity_id();

        Ok(Self::user_identifier(&user_id.as_owned()))
    }

    /// Build a [`UserIdentifier`] from a valid [`UserId`]
    pub fn user_identifier(user_id: &UserId) -> UserIdentifier {
        UserIdentifier::from(user_id.to_string())
    }

    /// Build a [`UserIdentifier`] from a valid [`UserId`]
    pub fn user_identifier_ref(user_id: UserIdRef<'_>) -> UserIdentifier {
        UserIdentifier::from(user_id.to_string())
    }
}

#[derive(Debug)]
pub struct ProtonMeetClaimExtractor(SdKbt);

impl ClaimExtractor for ProtonMeetClaimExtractor {
    fn credential_type(&self) -> mls_spec::defs::CredentialType {
        mls_spec::defs::CredentialType::new_unchecked(CREDENTIAL_SD_CWT)
    }

    fn get_claim(&self, query: &[u8]) -> Option<Vec<u8>> {
        let query: Query = Query::from_cbor_bytes(query).ok()?;
        let mut sd_kbt = self.0.clone();

        match &*query {
            _ => {
                // look for the claim in the SD-CWT (well technically in its payload or disclosures)
                sd_kbt.query(query).ok()?.and_then(|v| v.to_cbor_bytes().ok())
            }
        }
    }
}

impl ProtonMeetClaimExtractor {
    pub(crate) fn new(credential: Credential) -> Result<Self, MlsError> {
        match credential {
            Credential::Custom(CustomCredential {
                credential_type,
                data: sd_kbt,
            }) if *credential_type == mls_spec::defs::CredentialType::SD_CWT_CREDENTIAL => {
                Ok(Self(SdKbt::from_cbor_bytes(&sd_kbt).map_err(|_| {
                    MlsError::ImplementationError("Cannot deserialize SD-CWT")
                })?))
            }
            _ => Err(MlsError::ImplementationError("Expected a SD-CWT credential")),
        }
    }
}

#[cfg(feature = "test-utils")]
#[derive(Default, Debug, Clone)]
pub struct IdentityTester {
    #[allow(clippy::type_complexity)]
    pub validate_successor: Option<
        fn(
            &ProtonMeetIdentityProvider,
            predecessor: &SigningIdentity,
            successor: &SigningIdentity,
            _extensions: &ExtensionList,
        ) -> crate::MlsResult<bool>,
    >,
    #[allow(clippy::type_complexity)]
    pub validate_member: Option<
        fn(
            &ProtonMeetIdentityProvider,
            signing_identity: &SigningIdentity,
            timestamp: Option<MlsTime>,
            context: MemberValidationContext<'_>,
        ) -> crate::MlsResult<()>,
    >,
}
