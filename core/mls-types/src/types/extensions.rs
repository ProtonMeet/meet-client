use crate::{
    MediaTypeList, MlsTypesError, MlsTypesResult, mimi_protocol_mls::components::metadata::RoomMetadata, mls_spec,
};
use meet_identifiers::RoomId;
use mls_spec::{
    drafts::{mls_extensions::safe_application::Component, mls_extensions::safe_application::WireFormats},
    group::{ExternalSender, extensions::Extension},
    reexports::tls_codec,
};

#[derive(
    Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, tls_codec::TlsSize, tls_codec::TlsSerialize,
)]
pub struct Extensions(pub Vec<Extension>);

impl Extensions {
    pub fn into_inner(self) -> Vec<Extension> {
        self.0
    }

    pub fn app_data(&self) -> Option<&mls_spec::drafts::mls_extensions::safe_application::ApplicationDataDictionary> {
        self.iter().find_map(|e| match e {
            Extension::ApplicationData(app_data) => Some(app_data),
            _ => None,
        })
    }

    pub fn app_data_mut(
        &mut self,
    ) -> &mut mls_spec::drafts::mls_extensions::safe_application::ApplicationDataDictionary {
        if self.app_data().is_none() {
            self.0.push(Extension::ApplicationData(Default::default()));
        }
        self.iter_mut()
            .find_map(|e| match e {
                Extension::ApplicationData(app_data) => Some(app_data),
                _ => None,
            })
            // SAFETY: we just inserted the extension in case it was missing
            .unwrap_or_else(|| unreachable!("Application Data Extension cannot be missing"))
    }

    pub fn required_capabilities(&self) -> MlsTypesResult<&mls_spec::group::RequiredCapabilities> {
        self.iter()
            .find_map(|e| match e {
                Extension::RequiredCapabilities(rc) => Some(rc),
                _ => None,
            })
            .ok_or(MlsTypesError::ImplementationError("RequiredCapabilities is mandatory"))
    }

    pub fn required_capabilities_mut(&mut self) -> MlsTypesResult<&mut mls_spec::group::RequiredCapabilities> {
        self.iter_mut()
            .find_map(|e| match e {
                Extension::RequiredCapabilities(rc) => Some(rc),
                _ => None,
            })
            .ok_or(MlsTypesError::ImplementationError("RequiredCapabilities is mandatory"))
    }

    pub fn required_wire_formats(&self) -> Option<&WireFormats> {
        self.iter().find_map(|e| match e {
            Extension::RequiredWireFormats(wf) => Some(wf),
            _ => None,
        })
    }

    pub fn required_wire_formats_mut(&mut self) -> &mut WireFormats {
        if self.required_wire_formats().is_none() {
            self.0
                .push(Extension::RequiredWireFormats(WireFormats { wire_formats: vec![] }))
        }
        self.iter_mut()
            .find_map(|e| match e {
                Extension::RequiredWireFormats(wf) => Some(wf),
                _ => None,
            })
            // SAFETY: we just inserted the extension in case it was missing
            .unwrap_or_else(|| unreachable!("Application Data Extension cannot be missing"))
    }

    pub fn supported_wire_formats(&self) -> Option<&WireFormats> {
        self.iter().find_map(|e| match e {
            Extension::SupportedWireFormats(wf) => Some(wf),
            _ => None,
        })
    }

    pub fn supported_wire_formats_mut(&mut self) -> &mut WireFormats {
        if self.supported_wire_formats().is_none() {
            self.0
                .push(Extension::SupportedWireFormats(WireFormats { wire_formats: vec![] }))
        }
        self.iter_mut().find_map(|e| {
            match e {
                Extension::SupportedWireFormats(wf) => Some(wf),
                _ => None,
            }
        })
            // SAFETY: we just inserted the extension in case it was missing
            .unwrap_or_else(|| unreachable!("Application Data Extension cannot be missing"))
    }

    /// take that split borrow
    pub fn supported_wire_formats_mut_and_app_data_mut(
        &mut self,
    ) -> (
        &mut WireFormats,
        &mut mls_spec::drafts::mls_extensions::safe_application::ApplicationDataDictionary,
    ) {
        if self.supported_wire_formats().is_none() {
            self.0
                .push(Extension::SupportedWireFormats(WireFormats { wire_formats: vec![] }))
        }
        if self.app_data().is_none() {
            self.0.push(Extension::ApplicationData(Default::default()));
        }

        let (mut supported_wf, mut app_data_mut) = (None, None);

        for e in self.iter_mut() {
            match e {
                Extension::SupportedWireFormats(wf) => {
                    supported_wf.replace(wf);
                }
                Extension::ApplicationData(app_data) => {
                    app_data_mut.replace(app_data);
                }
                _ => {}
            }
        }

        // SAFETY: we just inserted the stuff in case it was missing
        (
            supported_wf.unwrap_or_else(|| unreachable!("SupportedWireFormats extension cannot be missing")),
            app_data_mut.unwrap_or_else(|| unreachable!("ApplicationData extension cannot be missing")),
        )
    }

    pub fn media_types(&self) -> Option<MediaTypeList> {
        self.app_data()?.extract_component::<MediaTypeList>().ok().flatten()
    }

    pub fn external_senders(&self) -> Option<&[ExternalSender]> {
        self.0.iter().find_map(|e| match e {
            Extension::ExternalSenders(senders) => Some(&senders[..]),
            _ => None,
        })
    }
}

impl From<Vec<Extension>> for Extensions {
    fn from(value: Vec<Extension>) -> Self {
        Self(value)
    }
}

impl std::ops::Deref for Extensions {
    type Target = [Extension];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Extensions {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub trait ExtensionListExt {
    fn application_data(&self) -> MlsTypesResult<Option<mls_rs::group::ApplicationDataDictionary>>;

    fn application_data_spec(
        &self,
    ) -> MlsTypesResult<Option<mls_spec::drafts::mls_extensions::safe_application::ApplicationDataDictionary>>;

    fn extract_component<C: Component>(&self) -> MlsTypesResult<Option<C>> {
        Ok(self
            .application_data_spec()?
            .map(|a| a.extract_component::<C>())
            .transpose()?
            .flatten())
    }

    fn room_id(&self) -> MlsTypesResult<Option<RoomId>> {
        self.extract_component::<RoomMetadata>()?
            .map(|r| r.room_uri.uri.parse().map_err(Into::into))
            .transpose()
    }
}

pub trait AppDataDictionaryExt {
    fn to_mls_rs_extension(&self) -> MlsTypesResult<mls_rs::Extension>;
}
