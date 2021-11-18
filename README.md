# 🌐 SSH Cfg

[![Crates.io](https://img.shields.io/crates/v/ssh_cfg.svg)](https://crates.io/crates/ssh_cfg)
[![docs.rs](https://img.shields.io/docsrs/ssh_cfg)](https://docs.rs/ssh_cfg)
![CI](https://github.com/azriel91/ssh_cfg/workflows/CI/badge.svg)

Parses `~/.ssh/config` asynchronously.

```rust
use ssh_cfg::SshConfigParser;

let ssh_config = SshConfigParser::parse_home().await?;
println!("{:?}", ssh_config);
```

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
