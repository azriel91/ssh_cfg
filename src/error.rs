use std::{fmt, io, path::PathBuf};

/// Errors when parsing SSH configuration.
#[derive(Debug)]
pub enum Error {
    /// Failed to discover the user's home directory.
    HomeDirectoryDiscoverFail,
    /// Failed to open SSH configuration file.
    SshConfigOpen {
        /// The path to the SSH file.
        path: PathBuf,
        /// The IO error.
        error: io::Error,
    },
    /// Unknown SSH option in the SSH configuration file.
    SshOptionUnknown {
        /// The configuration option key.
        key: String,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::HomeDirectoryDiscoverFail => {
                write!(f, "Failed to discover user's home directory.")
            }
            Self::SshConfigOpen { path, .. } => {
                write!(f, "Failed to open `{}`.", path.display())
            }
            Self::SshOptionUnknown { key } => {
                write!(f, "Unknown SSH configuration option `{}`.", key)
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::HomeDirectoryDiscoverFail => None,
            Self::SshConfigOpen { error, .. } => Some(error),
            Self::SshOptionUnknown { .. } => None,
        }
    }
}
