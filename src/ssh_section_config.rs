use std::ops::{Deref, DerefMut};

use indexmap::IndexMap;

use crate::SshOptionKey;

/// Keys for a particular SSH section.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SshSectionConfig(pub IndexMap<SshOptionKey, String>);

impl Deref for SshSectionConfig {
    type Target = IndexMap<SshOptionKey, String>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SshSectionConfig {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
