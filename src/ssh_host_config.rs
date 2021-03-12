use std::ops::{Deref, DerefMut};

use indexmap::IndexMap;

use crate::SshOptionKey;

/// Keys for a particular SSH host.
///
/// Ideally we don't store the values as strings, but actually parse them into a
/// strong data model.
#[derive(Clone, Debug, PartialEq)]
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
