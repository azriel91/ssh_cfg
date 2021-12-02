#![deny(missing_docs)]

//! Parses `~/.ssh/config` asynchronously.
//!
//! ```rust
//! use ssh_cfg::{SshConfigParser, SshOptionKey};
//! use tokio::runtime;
//!
//! async fn parse_ssh_config() -> Result<(), Box<dyn std::error::Error>> {
//!     let ssh_config = SshConfigParser::parse_home().await?;
//!
//!     // Print first host config
//!     if let Some((first_host, host_config)) = ssh_config.iter().next() {
//!         println!("Host: {}", first_host);
//!
//!         // Print its configured SSH key if any
//!         if let Some(identity_file) = host_config.get(&SshOptionKey::IdentityFile) {
//!             println!("  {} {}", SshOptionKey::IdentityFile, identity_file);
//!         }
//!     }
//!
//!     // Print all host configs
//!     println!();
//!     println!("{:#?}", ssh_config);
//!
//!     Ok(())
//! }
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let rt = runtime::Builder::new_current_thread().build()?;
//!     rt.block_on(parse_ssh_config())
//! }
//! ```
//!
//! Currently values are stored as `String`s. Ideally we would parse them into a
//! strong data model.

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
