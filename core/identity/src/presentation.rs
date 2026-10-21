use crate::{
    IdentityError, IdentityResult, ProtonEd25519SdCwtHolder, ProtonP256SdCwtHolder, SD_CWT_LEEWAY, SignatureAlgorithm,
    VerifiedSdCwt,
};
use core::time::Duration;
use meet_identifiers::RoomId;
use proton_claims::{
    UserAsserted,
    reexports::{
        CborPath, CwtStdLabel, Holder, HolderParams, HolderValidationParams, Presentation, SdCwtRead, TimeArg,
        TimeVerification, cose_key_set::CoseKeySet,
    },
};

/// SD-KBT audience of a [`PresentationContext::DsBearer`] presentation.
pub const DS_BEARER_AUDIENCE: &str = "meet-ds-bearer";

/// Lifetime of a [`PresentationContext::DsBearer`] presentation. Mint a fresh one per request.
pub const DS_BEARER_LIFETIME: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Disclosure {
    /// Disclose all the redacted claims of the SD-CWT
    Full,
    /// Disclose only the required claims for the DS to authenticate us
    DsBearer,
}

pub fn verify_sd_cwt(
    sd_cwt: &[u8],
    signing_keypair: Vec<u8>,
    alg: SignatureAlgorithm,
    cks: &CoseKeySet,
) -> IdentityResult<Box<VerifiedSdCwt>> {
    let params = HolderValidationParams {
        leeway: core::time::Duration::from_secs(30), // allow 30 seconds of time error, since server's nbf is set to 30s
        artificial_time: None,
        expected_subject: None,
        expected_issuer: None,
        expected_audience: None,
        expected_cnonce: None,
        time_verification: TimeVerification {
            verify_exp: true,
            verify_iat: false, // don't care and not set for privacy reasons
            verify_nbf: false, // same
        },
    };
    Ok(match alg {
        SignatureAlgorithm::Ed25519 => {
            let holder = ProtonEd25519SdCwtHolder::try_from(&signing_keypair[..])?;
            Box::new(holder.verify_sd_cwt(sd_cwt, params, cks)?)
        }
        SignatureAlgorithm::P256 => {
            let holder = ProtonP256SdCwtHolder::try_from(&signing_keypair[..])?;
            Box::new(holder.verify_sd_cwt(sd_cwt, params, cks)?)
        }
        SignatureAlgorithm::P384 => return Err(IdentityError::ImplementationError("P384 not yet implemented")),
    })
}

pub fn new_identity_presentation(
    signing_keypair: &[u8],
    alg: SignatureAlgorithm,
    mut sd_cwt: VerifiedSdCwt,
    disclosure: Disclosure,
    user_asserted: Option<UserAsserted>,
    ctx: &PresentationContext,
    artificial_time: Option<Duration>,
) -> IdentityResult<Vec<u8>> {
    let expiry = presentation_expiry(ctx, sd_cwt.0.exp()?);

    let presentation = match disclosure {
        Disclosure::Full => Presentation::Full,
        #[allow(clippy::match_like_matches_macro)] // will be easier to modify later
        Disclosure::DsBearer => Presentation::Path(Box::new(|path| match path {
            [CborPath::Int(i)] if *i == CwtStdLabel::Subject => true,
            _ => false,
        })),
    };

    let audience = presentation_audience(ctx);

    let presentation_params = HolderParams::<UserAsserted> {
        presentation,
        audience: audience.as_ref(),
        cnonce: None,
        expiry: Some(expiry),
        with_not_before: false,
        artificial_time,
        time_verification: TimeVerification {
            verify_exp: true,
            verify_iat: false, // don't care and not set for privacy reasons
            verify_nbf: false, // same
        },
        extra_kbt_unprotected: None,
        extra_kbt_protected: None,
        extra_kbt_payload: user_asserted,
        leeway: SD_CWT_LEEWAY,
    };

    let sd_kbt = match alg {
        SignatureAlgorithm::Ed25519 => {
            let holder = ProtonEd25519SdCwtHolder::try_from(signing_keypair)?;
            holder.new_presentation_raw(sd_cwt, presentation_params)
        }
        SignatureAlgorithm::P256 => {
            let holder = ProtonP256SdCwtHolder::try_from(signing_keypair)?;
            holder.new_presentation_raw(sd_cwt, presentation_params)
        }
        SignatureAlgorithm::P384 => return Err(IdentityError::ImplementationError("P384 not yet implemented")),
    }?;

    Ok(sd_kbt)
}

fn presentation_expiry(ctx: &PresentationContext, sd_cwt_exp: Option<i64>) -> TimeArg {
    /// A credential wrapping another must be shorter lived than the one it wraps
    #[cfg(not(any(test, feature = "test-utils")))]
    const PRESENTATION_LEEWAY: Duration = Duration::from_secs(5);
    #[cfg(any(test, feature = "test-utils"))]
    const PRESENTATION_LEEWAY: Duration = Duration::from_millis(1);

    // in case no expiry is defined
    const DEFAULT_EXPIRY: Duration = Duration::from_secs(3600 * 24 * 90); // 90 days

    match ctx {
        // The DS verifies the SD-CWT expiry independently, so outliving it grants nothing.
        PresentationContext::DsBearer => TimeArg::Relative(DS_BEARER_LIFETIME),
        _ => sd_cwt_exp
            .map(|e| Duration::from_secs(e as u64))
            .map(|e| e.saturating_sub(PRESENTATION_LEEWAY))
            .map(TimeArg::Absolute)
            .unwrap_or(TimeArg::Relative(DEFAULT_EXPIRY)),
    }
}

fn presentation_audience(ctx: &PresentationContext) -> std::borrow::Cow<'_, str> {
    match ctx {
        PresentationContext::CreateGroup { room_id }
        | PresentationContext::JoinGroupExternalCommit { room_id, .. }
        | PresentationContext::GroupReInit { room_id }
        | PresentationContext::NewKeyPackageForConsentRequest { room_id: Some(room_id) } => {
            std::borrow::Cow::Owned(room_id.to_string())
        }
        PresentationContext::DsBearer => std::borrow::Cow::Borrowed(DS_BEARER_AUDIENCE),
        _ => std::borrow::Cow::Borrowed(""),
    }
}

#[derive(Debug, Clone)]
pub enum PresentationContext {
    /// Creating a MLS group
    CreateGroup {
        room_id: RoomId,
    },
    /// Joining a group via external commit
    JoinGroupExternalCommit {
        room_id: RoomId,
    },
    /// Joining a group via external proposal
    JoinGroupExternalProposal {
        room_id: RoomId,
    },
    /// Doing a ReInit in a group
    GroupReInit {
        room_id: RoomId,
    },
    /// Update a credential in a group
    Update {
        room_id: RoomId,
    },
    /// Creating a new KeyPackage (contextless) and uploading it to the server
    NewKeyPackage,
    NewKeyPackageForConsentRequest {
        room_id: Option<RoomId>,
    },
    /// Used to authenticate to the MLS delivery service
    DsBearer,
    /// Default presentation, currently associated with full disclosure
    Default,
}

#[cfg(test)]
mod tests {
    use super::*;
    use meet_identifiers::Domain;

    const SD_CWT_EXP: i64 = 1_900_000_000;

    fn non_bearer_contexts() -> Vec<PresentationContext> {
        let room_id = RoomId::new(&"meet.proton.me".parse::<Domain>().unwrap());
        vec![
            PresentationContext::CreateGroup {
                room_id: room_id.clone(),
            },
            PresentationContext::JoinGroupExternalCommit {
                room_id: room_id.clone(),
            },
            PresentationContext::JoinGroupExternalProposal {
                room_id: room_id.clone(),
            },
            PresentationContext::GroupReInit {
                room_id: room_id.clone(),
            },
            PresentationContext::Update {
                room_id: room_id.clone(),
            },
            PresentationContext::NewKeyPackage,
            PresentationContext::NewKeyPackageForConsentRequest { room_id: Some(room_id) },
            PresentationContext::NewKeyPackageForConsentRequest { room_id: None },
            PresentationContext::Default,
        ]
    }

    #[test]
    fn ds_bearer_uses_dedicated_audience() {
        assert_eq!(
            presentation_audience(&PresentationContext::DsBearer),
            DS_BEARER_AUDIENCE
        );
    }

    #[test]
    fn credential_contexts_never_use_ds_bearer_audience() {
        for ctx in non_bearer_contexts() {
            assert_ne!(presentation_audience(&ctx), DS_BEARER_AUDIENCE, "{ctx:?}");
        }
    }

    #[test]
    fn ds_bearer_is_short_lived_regardless_of_sd_cwt_expiry() {
        for sd_cwt_exp in [Some(SD_CWT_EXP), None] {
            assert_eq!(
                presentation_expiry(&PresentationContext::DsBearer, sd_cwt_exp),
                TimeArg::Relative(DS_BEARER_LIFETIME)
            );
        }
    }

    #[test]
    fn credential_contexts_keep_sd_cwt_bound_expiry() {
        for ctx in non_bearer_contexts() {
            assert!(
                matches!(
                    presentation_expiry(&ctx, Some(SD_CWT_EXP)),
                    TimeArg::Absolute(exp) if exp < Duration::from_secs(SD_CWT_EXP as u64)
                ),
                "{ctx:?}"
            );
        }
    }
}
