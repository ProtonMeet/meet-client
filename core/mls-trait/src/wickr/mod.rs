use crate::{
    KvExt, MlsClientConfig,
    traits::client::KEY_PACKAGE_EXP_LEEWAY,
    wickr::{
        identity::ProtonMeetIdentityProvider,
        kv::{GroupKv, KeyPackageKv, PskKv},
        rules::ProtonMeetRules,
    },
};
use ::identity::{SD_CWT_LEEWAY, VerifiedSdCwt};
use mls_rs::Lifetime;
use mls_rs_core::{extension::ExtensionType, group::ProposalType, protocol_version::ProtocolVersion, time::MlsTime};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use mls_types::CipherSuite;
use proton_claims::reexports::{SdCwtRead, cose_key_set::CoseKeySet};
use std::time::{Duration, UNIX_EPOCH};

pub mod authorization;
pub mod client;
pub mod commit_output;
pub mod crypto;
mod debug;
pub mod error;
pub mod group;
pub mod identity;
pub mod kv;
pub mod rules;
pub mod types;

#[derive(Debug, Clone)]
pub struct StdMlsClientConfig<Kv> {
    pub config: MlsClientConfig,
    pub kv: Kv,
    pub idp: ProtonMeetIdentityProvider,
    pub crypto_provider: RustCryptoProvider,
    pub rules: ProtonMeetRules,
    sd_cwt: VerifiedSdCwt,
    sd_cwt_expiration: Duration,
    _marker: core::marker::PhantomData<Kv>,
}

impl<Kv: KvExt + Send + Sync + Clone> StdMlsClientConfig<Kv> {
    /// IN case not specified in the SD-CWT
    const DEFAULT_EXPIRATION: Duration = Duration::from_secs(90 * 24 * 3600);

    pub fn new(
        cs: CipherSuite,
        auth_cks: &CoseKeySet,
        server_cks: &CoseKeySet,
        config: MlsClientConfig,
        kv: Kv,
        mut sd_cwt: VerifiedSdCwt,
    ) -> Self {
        let crypto_provider = RustCryptoProvider::with_enabled_cipher_suites(vec![cs.into()]);
        let idp = ProtonMeetIdentityProvider::new(auth_cks, server_cks, config.clone());
        let rules = ProtonMeetRules::new(config.clone(), auth_cks.clone());
        let sd_cwt_expiration = sd_cwt.0.exp().ok().flatten();
        #[allow(clippy::unwrap_used)]
        let sd_cwt_expiration = sd_cwt_expiration
            .map(|e| Duration::from_secs(e as u64))
            .unwrap_or_else(|| {
                std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap() + Self::DEFAULT_EXPIRATION
            });
        Self {
            config,
            kv,
            idp,
            crypto_provider,
            rules,
            sd_cwt,
            sd_cwt_expiration,
            _marker: Default::default(),
        }
    }

    pub fn set_sd_cwt(&mut self, mut sd_cwt: VerifiedSdCwt) {
        #[allow(clippy::unwrap_used)]
        let sd_cwt_expiration = sd_cwt
            .0
            .exp()
            .ok()
            .flatten()
            .map(|e| Duration::from_secs(e as u64))
            .unwrap_or_else(|| {
                std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap() + Self::DEFAULT_EXPIRATION
            });
        self.sd_cwt = sd_cwt;
        self.sd_cwt_expiration = sd_cwt_expiration;
    }
}

impl<Kv: KvExt + Send + Sync + Clone> mls_rs::client_config::ClientConfig for StdMlsClientConfig<Kv> {
    type KeyPackageRepository = KeyPackageKv<Kv>;
    type PskStore = PskKv<Kv>;
    type GroupStateStorage = GroupKv<Kv>;
    type IdentityProvider = ProtonMeetIdentityProvider;
    type MlsRules = ProtonMeetRules;
    type CryptoProvider = RustCryptoProvider;

    fn supported_extensions(&self) -> Vec<ExtensionType> {
        self.config.supported_extensions()
    }

    fn supported_custom_proposals(&self) -> Vec<ProposalType> {
        self.config.supported_proposal_type()
    }

    fn supported_protocol_versions(&self) -> Vec<ProtocolVersion> {
        self.config.supported_protocol_versions()
    }

    fn key_package_repo(&self) -> Self::KeyPackageRepository {
        KeyPackageKv(self.kv.clone())
    }

    fn mls_rules(&self) -> Self::MlsRules {
        self.rules.clone()
    }

    fn secret_store(&self) -> Self::PskStore {
        PskKv(self.kv.clone())
    }

    fn group_state_storage(&self) -> Self::GroupStateStorage {
        GroupKv(self.kv.clone())
    }

    fn identity_provider(&self) -> Self::IdentityProvider {
        self.idp.clone()
    }

    fn crypto_provider(&self) -> Self::CryptoProvider {
        self.crypto_provider.clone()
    }

    fn lifetime(&self, now: Option<MlsTime>) -> Lifetime {
        let now = now.unwrap_or_else(MlsTime::now).seconds_since_epoch();
        let not_before = MlsTime::from_duration_since_epoch(std::time::Duration::from_secs(
            now.saturating_sub(SD_CWT_LEEWAY.as_secs()),
        ));
        // here we want to take the expiration from the wrapped credential (SD-CWT in our case) so
        // we override mls-rs implementation of this because it was doing 'now + exp'.
        let mut not_after = self.sd_cwt_expiration;
        not_after = not_after.saturating_sub(KEY_PACKAGE_EXP_LEEWAY);
        Lifetime::new(not_before, MlsTime::from_duration_since_epoch(not_after))
    }
}
