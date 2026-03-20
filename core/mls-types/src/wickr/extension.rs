use crate::{
    Extensions, MlsTypesError, MlsTypesResult,
    mls_spec::{
        self,
        defs::ExtensionType,
        drafts::mls_extensions::safe_application::{ApplicationDataDictionary, WireFormats},
        group::{
            ExternalSender, RequiredCapabilities,
            extensions::{Extension, ExternalPub, RatchetTreeExtension},
        },
    },
    tls_codec::{Deserialize, Serialize},
    types::extensions::{AppDataDictionaryExt, ExtensionListExt},
};
use mls_rs::{Extension as WickrExtension, extension::ExtensionType as WickrExtensionType};
use mls_rs_codec::{MlsDecode, MlsEncode};

impl TryFrom<Extensions> for mls_rs::ExtensionList {
    type Error = MlsTypesError;

    fn try_from(value: Extensions) -> Result<Self, Self::Error> {
        Ok(Self::from_iter(
            value
                .into_inner()
                .into_iter()
                .map(from_mls_spec_extension)
                .collect::<MlsTypesResult<Vec<_>>>()?,
        ))
    }
}

impl TryFrom<mls_rs::ExtensionList> for Extensions {
    type Error = MlsTypesError;

    fn try_from(value: mls_rs::ExtensionList) -> Result<Self, Self::Error> {
        Ok(value
            .0
            .into_iter()
            .map(to_mls_spec_extension)
            .collect::<MlsTypesResult<Vec<_>>>()?
            .into())
    }
}

fn from_mls_spec_extension(e: Extension) -> MlsTypesResult<WickrExtension> {
    Ok(match e {
        Extension::ApplicationId(b) => WickrExtension::new(WickrExtensionType::APPLICATION_ID, b),
        Extension::RatchetTree(b) => WickrExtension::new(WickrExtensionType::RATCHET_TREE, b.tls_serialize_detached()?),
        Extension::RequiredCapabilities(b) => {
            WickrExtension::new(WickrExtensionType::REQUIRED_CAPABILITIES, b.tls_serialize_detached()?)
        }
        Extension::ExternalPub(b) => WickrExtension::new(WickrExtensionType::EXTERNAL_PUB, b.tls_serialize_detached()?),
        Extension::ExternalSenders(b) => {
            WickrExtension::new(WickrExtensionType::EXTERNAL_SENDERS, b.tls_serialize_detached()?)
        }
        Extension::ApplicationData(b) => WickrExtension::new(
            WickrExtensionType::new(mls_spec::drafts::mls_extensions::EXTENSION_APP_DATA_DICT),
            b.tls_serialize_detached()?,
        ),
        Extension::SupportedWireFormats(b) => WickrExtension::new(
            WickrExtensionType::new(mls_spec::drafts::mls_extensions::EXTENSION_SUPPORTED_WIRE_FORMATS),
            b.tls_serialize_detached()?,
        ),
        Extension::RequiredWireFormats(b) => WickrExtension::new(
            WickrExtensionType::new(mls_spec::drafts::mls_extensions::EXTENSION_REQUIRED_WIRE_FORMATS),
            b.tls_serialize_detached()?,
        ),
        _ => return Err(MlsTypesError::ImplementationError("Unsupported extension")),
    })
}

fn to_mls_spec_extension(e: WickrExtension) -> MlsTypesResult<Extension> {
    Ok(match e.extension_type.raw_value() {
        ExtensionType::APPLICATION_ID => Extension::ApplicationId(e.extension_data),
        ExtensionType::RATCHET_TREE => {
            Extension::RatchetTree(RatchetTreeExtension::tls_deserialize(&mut e.extension_data.as_slice())?)
        }
        ExtensionType::REQUIRED_CAPABILITIES => {
            Extension::RequiredCapabilities(RequiredCapabilities::tls_deserialize(&mut e.extension_data.as_slice())?)
        }
        ExtensionType::EXTERNAL_PUB => {
            Extension::ExternalPub(ExternalPub::tls_deserialize(&mut e.extension_data.as_slice())?)
        }
        ExtensionType::EXTERNAL_SENDERS => Extension::ExternalSenders(Vec::<ExternalSender>::tls_deserialize(
            &mut e.extension_data.as_slice(),
        )?),
        ExtensionType::SUPPORTED_WIRE_FORMATS => {
            Extension::SupportedWireFormats(WireFormats::tls_deserialize(&mut e.extension_data.as_slice())?)
        }
        ExtensionType::REQUIRED_WIRE_FORMATS => {
            Extension::RequiredWireFormats(WireFormats::tls_deserialize(&mut e.extension_data.as_slice())?)
        }
        mls_spec::drafts::mls_extensions::EXTENSION_APP_DATA_DICT => Extension::ApplicationData(
            ApplicationDataDictionary::tls_deserialize(&mut e.extension_data.as_slice())?,
        ),
        _ => return Err(MlsTypesError::WickrConversionError("Unknown")),
    })
}

impl ExtensionListExt for mls_rs::ExtensionList {
    fn application_data(&self) -> MlsTypesResult<Option<mls_rs::group::ApplicationDataDictionary>> {
        Ok(self
            .iter()
            .find_map(|extension| {
                if extension.extension_type == mls_spec::drafts::mls_extensions::EXTENSION_APP_DATA_DICT.into() {
                    Some(mls_rs::group::ApplicationDataDictionary::mls_decode(
                        &mut extension.extension_data.as_slice(),
                    ))
                } else {
                    None
                }
            })
            .transpose()?)
    }

    fn application_data_spec(&self) -> MlsTypesResult<Option<ApplicationDataDictionary>> {
        Ok(self
            .iter()
            .find_map(|extension| {
                if extension.extension_type == mls_spec::drafts::mls_extensions::EXTENSION_APP_DATA_DICT.into() {
                    let bytes = &mut extension.extension_data.as_slice();
                    Some(
                        mls_spec::drafts::mls_extensions::safe_application::ApplicationDataDictionary::tls_deserialize(
                            bytes,
                        ),
                    )
                } else {
                    None
                }
            })
            .transpose()?)
    }
}

impl AppDataDictionaryExt for mls_rs::group::ApplicationDataDictionary {
    fn to_mls_rs_extension(&self) -> MlsTypesResult<mls_rs::Extension> {
        Ok(mls_rs::Extension::new(
            mls_rs::extension::ExtensionType::new(mls_spec::drafts::mls_extensions::EXTENSION_APP_DATA_DICT),
            self.mls_encode_to_vec()?,
        ))
    }
}

#[inline(always)]
pub fn mls_spec_to_mls_rs(value: mls_spec::defs::ExtensionType) -> mls_rs::extension::ExtensionType {
    mls_rs::extension::ExtensionType::from(*value)
}
