#![deny(missing_docs)]

//! Parses `~/.ssh/config` asynchronously.
//!
//! ```rust
//! use ssh_cfg::SshConfigParser;
//! # use tokio::runtime;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let rt  = runtime::Builder::new_current_thread().build()?;
//! #
//! # rt.block_on(async {
//! let ssh_config = SshConfigParser::parse_home().await?;
//! println!("{:?}", ssh_config);
//! # Ok(())
//! # })
//! # }
//! ```
//!
//! Currently this only stores values as `String`s. Ideally we would parse them
//! into a strong data model.
//!
//! # SSH Config
//!
//! ssh(1) obtains configuration data from the following sources in the
//! following order:
//!
//! 1. Command-line options
//! 2. User's configuration file (`~/.ssh/config`)
//! 3. System-wide configuration file (`/etc/ssh/ssh_config`)
//!
//! For each parameter, the first obtained value will be used. The configuration
//! files contain sections separated by `Host` specifications, and that
//! section is only applied for hosts that match one of the patterns given in
//! the specification. The matched host name is the one given on the command
//! line.
//!
//! Since the first obtained value for each parameter is used, more
//! host-specific declarations should be given near the beginning of the file,
//! and general defaults at the end.
//!
//! The configuration file has the following format:
//!
//! Empty lines and lines starting with `#` are comments. Otherwise a line is of
//! the format `keyword arguments`. Configuration options may be separated by
//! whitespace or optional whitespace and exactly one `=`; the latter format is
//! useful to avoid the need to quote whitespace when specifying configuration
//! options using the ssh, scp, and sftp -o option. Arguments may optionally be
//! enclosed in double quotes (`"`) in order to represent arguments containing
//! spaces.
//!
//! ## Patterns
//!
//! A pattern consists of zero or more non-whitespace characters, `*` (a
//! wildcard that matches zero or more characters), or `?` (a wildcard that
//! matches exactly one character). For example, to specify a set of
//! declarations for any host in the `.co.uk` set of domains, the following
//! pattern could be used:
//!
//! ```text
//! Host *.co.uk
//! ```
//!
//! The following pattern would match any host in the 192.168.0.[0-9] network
//! range:
//!
//! ```text
//! Host 192.168.0.?
//! ```
//!
//! A pattern-list is a comma-separated list of patterns. Patterns within
//! pattern-lists may be negated by preceding them with an exclamation mark
//! (`!`). For example, to allow a key to be used from anywhere within an
//! organisation except from the `dialup` pool, the following entry (in
//! authorized_keys) could be used:
//!
//! ```text
//! from="!*.dialup.example.com,*.example.com"
//! ```

pub use crate::{
    config_error::ConfigError, error::Error, ssh_config::SshConfig,
    ssh_config_parser::SshConfigParser, ssh_host_config::SshHostConfig,
    ssh_option_key::SshOptionKey,
};

mod config_error;
mod error;
mod ssh_config;
mod ssh_config_parser;
mod ssh_host_config;
mod ssh_option_key;
