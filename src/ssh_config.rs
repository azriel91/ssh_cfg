use std::ops::{Deref, DerefMut};

use indexmap::IndexMap;

use crate::{SshSection, SshSectionConfig};

/// Parsed SSH config file.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SshConfig(pub IndexMap<SshSection, SshSectionConfig>);

impl Deref for SshConfig {
    type Target = IndexMap<SshSection, SshSectionConfig>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SshConfig {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
