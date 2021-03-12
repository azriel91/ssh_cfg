#![deny(missing_docs)]

//! Parses ~/.ssh/config asynchronously.

pub use crate::{error::Error, ssh_config::SshConfig, ssh_config_parser::SshConfigParser};

mod error;
mod ssh_config;
mod ssh_config_parser;
