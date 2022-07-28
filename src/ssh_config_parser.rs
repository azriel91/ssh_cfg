use std::path::Path;

use plain_path::PlainPathExt;

use crate::{ConfigError, Error, SshConfig, SshOptionKey, SshSection, SshSectionConfig};

/// Parses SSH configuration file into [`SshConfig`].
pub struct SshConfigParser;

// See https://github.com/substack/libssh/blob/master/src/config.c
impl SshConfigParser {
    /// Returns the parsed SSH configuration.
    pub async fn parse(path: &Path) -> Result<SshConfig, Error> {
        let path = path.plain()?;

        let contents = Self::ssh_config_contents(&path).await?;
        let ssh_config = Self::parse_config_contents(&contents)?;

        Ok(ssh_config)
    }

    /// Parses `~/.ssh/config`.
    pub async fn parse_home() -> Result<SshConfig, Error> {
        if let Some(mut ssh_path) = dirs::home_dir() {
            ssh_path.push(".ssh");
            ssh_path.push("config");
            Self::parse(&ssh_path).await
        } else {
            Err(Error::HomeDirNotFound)
        }
    }

    async fn ssh_config_contents(path: &Path) -> Result<String, Error> {
        async_fs::read_to_string(path)
            .await
            .map_err(|error| Error::SshConfigRead {
                path: path.to_path_buf(),
                error,
            })
    }

    /// Parses SSH configuration in memory.
    ///
    /// # Parameters
    ///
    /// * `ssh_config_contents`: The SSH configuration.
    pub fn parse_config_contents(ssh_config_contents: &str) -> Result<SshConfig, Error> {
        let mut errors = Vec::new();
        let kv_pairs = Self::kv_pairs(ssh_config_contents, &mut errors).into_iter();

        let mut ssh_config = SshConfig::default();
        let mut current_section = None;
        let mut ssh_section_config = SshSectionConfig::default();
        for (key, value) in kv_pairs {
            let ssh_option_key = match key.parse::<SshOptionKey>() {
                Ok(ssh_option_key) => ssh_option_key,
                Err(error) => {
                    errors.push(error);
                    continue;
                }
            };

            // Check if we're starting a new section,
            // if so we need to save the last parsed section.
            if let SshOptionKey::Host | SshOptionKey::Match = ssh_option_key {
                if let Some(current_section) = current_section.take() {
                    ssh_config.insert(current_section, ssh_section_config);

                    // Initialize new config for the next host.
                    ssh_section_config = SshSectionConfig::default();
                }

                current_section = Some(match ssh_option_key {
                    SshOptionKey::Host => SshSection::Host(value.to_string()),
                    SshOptionKey::Match => SshSection::Match(value.to_string()),
                    _ => unreachable!("Guarded by condition"),
                });
            } else if SshOptionKey::Include == ssh_option_key {
                if current_section.is_some() {
                    ssh_section_config.insert(ssh_option_key, value.to_string());
                } else {
                    current_section = Some(SshSection::Include(value.to_string()))
                }
            } else {
                // Only `Host` and `Match` sections are allowed to have other keys
                match current_section {
                    Some(SshSection::Host(_) | SshSection::Match(_)) => {
                        ssh_section_config.insert(ssh_option_key, value.to_string());
                    }
                    Some(SshSection::Include(_)) | None => {
                        errors.push(ConfigError::SshOptionBeforeHostOrMatch {
                            option: ssh_option_key,
                            value: value.to_string(),
                        });
                    }
                }
            }
        }

        // Insert the final section's config.
        if let Some(current_section) = current_section.take() {
            ssh_config.insert(current_section, ssh_section_config);
        }

        if errors.is_empty() {
            Ok(ssh_config)
        } else {
            Err(Error::ConfigErrors { errors })
        }
    }

    fn kv_pairs<'f>(
        ssh_config_contents: &'f str,
        config_errors: &mut Vec<ConfigError>,
    ) -> Vec<(&'f str, &'f str)> {
        ssh_config_contents
            .lines()
            // Only consider content before the first `#`
            .map(|line| line.split_once('#').map_or(line, |split| split.0))
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .filter_map(|line| {
                // Key and value are either separated by `=`, or whitespace.
                // We try split by `=` first, and if there are two tokens, then those are
                // the key and value pair. Otherwise we split the first token by ` `.
                let kv_pair = Self::kv_split_by(line, '=').or_else(|| Self::kv_split_by(line, ' '));
                if kv_pair.is_none() {
                    config_errors.push(ConfigError::KeyValueNotFound {
                        line: line.to_string(),
                    });
                }

                kv_pair
            })
            .collect::<Vec<_>>()
    }

    /// Returns the key and value split by the given character.
    fn kv_split_by(line: &str, separator: char) -> Option<(&str, &str)> {
        let mut kv_split = line.splitn(2, separator);
        let key = kv_split.next();
        let value = kv_split.next();

        match (key, value) {
            (Some(key), Some(value)) => Some((key.trim(), value.trim())),
            (Some(_), None) => None,
            _ => unreachable!("Empty lines are filtered."),
        }
    }
}
