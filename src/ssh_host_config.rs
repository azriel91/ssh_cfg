use std::ops::{Deref, DerefMut};

use indexmap::IndexMap;

use crate::SshOptionKey;

/// Keys for a particular SSH host.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SshHostConfig(pub IndexMap<SshOptionKey, String>);

impl Deref for SshHostConfig {
    type Target = IndexMap<SshOptionKey, String>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SshHostConfig {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
