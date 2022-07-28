# Changelog

## unreleased

### Added

* `SshSection` to switch between different kinds of SSH sections. ([#3], [#4])

### Changes

* ***Breaking:*** `SshHostConfig` renamed to `SshSectionConfig`.
* ***Breaking:*** `SshConfig` stores `IndexMap<SshSection, _>` instead of `IndexMap<String, _>`.
* ***Breaking:*** `Error::SshOptionBeforeHost` renamed to `Error::SshOptionBeforeHostOrMatch`.

[#3]: https://github.com/azriel91/ssh_cfg/issues/3
[#4]: https://github.com/azriel91/ssh_cfg/pull/4


## 0.3.0

### Added

* Support parsing SSH configuration files with only `Host` configurations.

