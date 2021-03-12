use std::{borrow::Cow, path::Path};

use async_fs::File;

use crate::{Error, SshConfig};

/// Parses SSH configuration file into [`SshConfig`].
pub struct SshConfigParser;

// See https://github.com/substack/libssh/blob/master/src/config.c
impl SshConfigParser {
    /// Returns the parsed SSH configuration.
    pub async fn parse(path: &Path) -> Result<SshConfig, Error> {
        let path_normalized = Self::path_normalize(path)?;

        let _ssh_file =
            File::open(&path_normalized)
                .await
                .map_err(|error| Error::SshConfigOpen {
                    path: path_normalized.into_owned(),
                    error,
                })?;

        Ok(SshConfig {})
    }

    /// Parses `~/.ssh/config`.
    pub async fn parse_home() -> Result<SshConfig, Error> {
        if let Some(mut ssh_path) = dirs::home_dir() {
            ssh_path.push(".ssh");
            ssh_path.push("config");
            Self::parse(&ssh_path).await
        } else {
            Err(Error::HomeDirectoryDiscoverFail)
        }
    }

    fn path_normalize(path: &Path) -> Result<Cow<'_, Path>, Error> {
        if path.starts_with("~") {
            // Replace `~` with user's home directory.
            if let Some(mut path_normalized) = dirs::home_dir() {
                path_normalized.extend(path.into_iter().skip(1));
                Ok(Cow::Owned(path_normalized))
            } else {
                Err(Error::HomeDirectoryDiscoverFail)
            }
        } else {
            Ok(Cow::Borrowed(path))
        }
    }
}
