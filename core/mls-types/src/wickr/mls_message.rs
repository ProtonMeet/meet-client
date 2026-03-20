impl From<crate::MlsMessage> for mls_rs::MlsMessage {
    fn from(msg: crate::MlsMessage) -> Self {
        *msg.mls_message
    }
}

impl From<mls_rs::MlsMessage> for crate::MlsMessage {
    fn from(msg: mls_rs::MlsMessage) -> Self {
        Self {
            mls_message: Box::new(msg),
            virtual_time: None,
        }
    }
}
