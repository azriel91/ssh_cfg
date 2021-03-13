use std::{fmt, io, path::PathBuf};

use crate::ConfigError;

/// Errors when parsing SSH configuration.
#[derive(Debug)]
pub enum Error {
    /// SSH configuration file contains errors.
    ConfigErrors {
        /// The underlying configuration errors
        errors: Vec<ConfigError>,
    },
    /// Failed to discover the user's home directory.
    HomeDirectoryDiscoverFail,
    /// Failed to read SSH configuration file.
    SshConfigRead {
        /// The path to the SSH file.
        path: PathBuf,
        /// The IO error.
        error: io::Error,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::ConfigErrors { errors } => {
                writeln!(f, "SSH configuration contains the following errors:\n")?;

                errors
                    .iter()
                    .try_for_each(|error| writeln!(f, "* {}", error))?;

                writeln!(f)
            }
            Self::HomeDirectoryDiscoverFail => {
                write!(f, "Failed to discover user's home directory.")
            }
            Self::SshConfigRead { path, .. } => {
                write!(f, "Failed to read `{}`.", path.display())
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ConfigErrors { .. } => None,
            Self::HomeDirectoryDiscoverFail => None,
            Self::SshConfigRead { error, .. } => Some(error),
        }
    }
}
