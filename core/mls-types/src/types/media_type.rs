use crate::mls_spec::drafts::mls_extensions::{self, content_advertisement, safe_application};
use meet_mls::reexports::mimi_protocol_mls::reexports::tls_codec;
use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};

/// See https://www.ietf.org/archive/id/draft-ietf-mls-extensions-05.html#section-3.3.2
#[derive(Debug, Clone, PartialEq, Eq, Hash, MlsSize, MlsEncode, MlsDecode, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MediaTypeParameter {
    // Example "charset"
    pub name: String,
    // Example "utf8"
    pub value: String,
}

/// See https://www.ietf.org/archive/id/draft-ietf-mls-extensions-05.html#section-3.3.2
#[derive(Debug, Clone, PartialEq, Eq, Hash, MlsSize, MlsEncode, MlsDecode, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MediaType {
    // Example `text/plain`
    pub media_type: String,
    #[serde(default)]
    pub parameters: Vec<MediaTypeParameter>,
}

impl Default for MediaType {
    fn default() -> Self {
        Self {
            media_type: "text/plain".into(),
            parameters: vec![MediaTypeParameter {
                name: "charset".into(),
                value: "UTF-8".into(),
            }],
        }
    }
}

fn string_from_bytes(bytes: Vec<u8>) -> Result<String, crate::MlsTypesError> {
    Ok(String::from_utf8(bytes).map_err(|_| tls_codec::Error::InvalidInput)?)
}

impl From<MediaType> for content_advertisement::MediaType {
    fn from(val: MediaType) -> Self {
        Self {
            media_type: val.media_type.into_bytes(),
            parameters: val
                .parameters
                .into_iter()
                .map(|p| content_advertisement::Parameter {
                    parameter_name: p.name.into_bytes(),
                    parameter_value: p.value.into_bytes(),
                })
                .collect(),
        }
    }
}

impl TryFrom<content_advertisement::MediaType> for MediaType {
    type Error = crate::MlsTypesError;

    fn try_from(value: content_advertisement::MediaType) -> Result<Self, Self::Error> {
        Ok(Self {
            media_type: string_from_bytes(value.media_type)?,
            parameters: value
                .parameters
                .into_iter()
                .map(|p| {
                    Ok(MediaTypeParameter {
                        name: string_from_bytes(p.parameter_name)?,
                        value: string_from_bytes(p.parameter_value)?,
                    })
                })
                .collect::<Result<Vec<_>, Self::Error>>()?,
        })
    }
}

/// See https://www.ietf.org/archive/id/draft-ietf-mls-extensions-05.html#section-3.3.2
#[derive(Default, Debug, Clone, MlsSize, MlsEncode, MlsDecode, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
#[repr(transparent)]
pub struct MediaTypeList(pub Vec<MediaType>);

impl From<Vec<MediaType>> for MediaTypeList {
    fn from(value: Vec<MediaType>) -> Self {
        Self(value)
    }
}

impl TryFrom<content_advertisement::MediaTypeList> for MediaTypeList {
    type Error = crate::MlsTypesError;

    fn try_from(value: content_advertisement::MediaTypeList) -> Result<Self, Self::Error> {
        let media_types = value
            .media_types
            .into_iter()
            .map(|mt| mt.try_into())
            .collect::<Result<Vec<_>, Self::Error>>()?;
        Ok(Self(media_types))
    }
}

impl From<MediaTypeList> for content_advertisement::MediaTypeList {
    fn from(val: MediaTypeList) -> Self {
        let media_types = val.0.into_iter().map(|mt| mt.into()).collect::<Vec<_>>();
        Self { media_types }
    }
}

impl MediaTypeList {
    #[inline]
    #[allow(clippy::unwrap_used)]
    pub(crate) fn to_mls_spec(&self) -> content_advertisement::MediaTypeList {
        self.clone().into()
    }

    #[inline]
    pub(crate) fn from_mls_spec(mtl: content_advertisement::MediaTypeList) -> crate::MlsTypesResult<Self> {
        Self::try_from(mtl)
    }
}

impl tls_codec::Size for MediaTypeList {
    fn tls_serialized_len(&self) -> usize {
        self.to_mls_spec().tls_serialized_len()
    }
}

impl tls_codec::Serialize for MediaTypeList {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        self.to_mls_spec().tls_serialize(writer)
    }
}

impl tls_codec::Deserialize for MediaTypeList {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let mtl = content_advertisement::MediaTypeList::tls_deserialize(bytes)?;
        Self::from_mls_spec(mtl).map_err(|_| tls_codec::Error::InvalidInput)
    }
}

impl safe_application::Component for MediaTypeList {
    fn component_id() -> safe_application::ComponentId {
        mls_extensions::CONTENT_MEDIA_TYPES_ID
    }
}
