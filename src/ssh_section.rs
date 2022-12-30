use std::fmt;

/// SSH configuration blocks
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SshSection {
    /// `Host` configuration.
    Host(String),
    /// `Match` configuration.
    Match(String),
    /// Top level include.
    Include(String),
}

impl fmt::Display for SshSection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Host(host) => write!(f, "Host {host}"),
            Self::Match(r#match) => write!(f, "Match {match}"),
            Self::Include(include) => write!(f, "Include {include}"),
        }
    }
}
