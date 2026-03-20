impl From<crate::Welcome> for mls_rs::group::Welcome {
    fn from(msg: crate::Welcome) -> Self {
        msg.0
    }
}

impl From<mls_rs::group::Welcome> for crate::Welcome {
    fn from(welcome: mls_rs::group::Welcome) -> Self {
        Self(welcome)
    }
}

impl<'w> From<&'w mls_rs::group::Welcome> for crate::WelcomeRef<'w> {
    fn from(welcome: &'w mls_rs::group::Welcome) -> Self {
        Self(welcome)
    }
}
