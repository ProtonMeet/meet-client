use crate::types::content_type::ContentType;
use mls_rs::group::ContentType as WickrContentType;

impl From<WickrContentType> for ContentType {
    fn from(ct: WickrContentType) -> Self {
        match ct {
            WickrContentType::Application => Self::Application,
            WickrContentType::Proposal => Self::Proposal,
            WickrContentType::Commit => Self::Commit,
        }
    }
}

impl From<ContentType> for WickrContentType {
    fn from(ct: ContentType) -> Self {
        match ct {
            ContentType::Application => Self::Application,
            ContentType::Proposal => Self::Proposal,
            ContentType::Commit => Self::Commit,
        }
    }
}
