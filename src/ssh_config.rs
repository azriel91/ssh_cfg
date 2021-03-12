use std::ops::{Deref, DerefMut};

use indexmap::IndexMap;

use crate::{SshHostConfig, SshOptionKey};

/// Parsed SSH config file.
#[derive(Clone, Debug, PartialEq)]
pub struct SshConfig(pub IndexMap<SshOptionKey, SshHostConfig>);

impl Deref for SshConfig {
    type Target = IndexMap<SshOptionKey, SshHostConfig>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SshConfig {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
