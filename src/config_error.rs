use std::fmt;

use crate::SshOptionKey;

/// Errors when parsing SSH config file.
#[derive(Debug)]
pub enum ConfigError {
    /// An SSH option is provided before the `Host` key.
    SshOptionBeforeHostOrMatch {
        /// The SSH option.
        option: SshOptionKey,
        /// Value provided to the key.
        value: String,
    },
    /// Unknown SSH option in the SSH configuration file.
    SshOptionUnknown {
        /// The configuration option key.
        key: String,
    },
    /// Line could not be parsed into a key and value pair.
    KeyValueNotFound {
        /// The line that could not be parsed.
        line: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::SshOptionBeforeHostOrMatch { option, .. } => {
                write!(
                    f,
                    "SSH option `{option}` provided before `Host` or `Match` is specified.",
                )
            }
            Self::SshOptionUnknown { key } => {
                write!(f, "Unknown SSH configuration option `{key}`.")
            }
            Self::KeyValueNotFound { line } => write!(
                f,
                "Could not determine key / value for this line: `{line}`.\n\
                    Key / value pairs must be separated by ` ` or `=`."
            ),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SshOptionBeforeHostOrMatch { .. } => None,
            Self::SshOptionUnknown { .. } => None,
            Self::KeyValueNotFound { .. } => None,
        }
    }
}
