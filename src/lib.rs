#![deny(missing_docs)]

//! Parses ~/.ssh/config asynchronously.

pub use crate::{
    error::Error, ssh_config::SshConfig, ssh_config_parser::SshConfigParser,
    ssh_host_config::SshHostConfig, ssh_option_key::SshOptionKey,
};

mod error;
mod ssh_config;
mod ssh_config_parser;
mod ssh_host_config;
mod ssh_option_key;
