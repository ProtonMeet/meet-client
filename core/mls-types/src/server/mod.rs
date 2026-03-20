//! TODO: highly inefficient but helps mapping without exposing all the internals of mls-rs

use crate::MlsTypesResult;
use crate::mls_spec;
use crate::types::extensions::AppDataDictionaryExt;
use mls_spec::Serializable;

mod credential;
mod message;
mod rt;

impl AppDataDictionaryExt for mls_spec::drafts::mls_extensions::safe_application::ApplicationDataDictionary {
    fn to_mls_rs_extension(&self) -> MlsTypesResult<mls_rs::Extension> {
        Ok(mls_rs::Extension::new(
            mls_rs::extension::ExtensionType::new(mls_spec::drafts::mls_extensions::EXTENSION_APP_DATA_DICT),
            self.to_tls_bytes()?,
        ))
    }
}
