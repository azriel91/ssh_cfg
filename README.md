# 🌐 SSH Cfg

[![Crates.io](https://img.shields.io/crates/v/ssh_cfg.svg)](https://crates.io/crates/ssh_cfg)
[![docs.rs](https://img.shields.io/docsrs/ssh_cfg)](https://docs.rs/ssh_cfg)
[![CI](https://github.com/azriel91/ssh_cfg/workflows/CI/badge.svg)](https://github.com/azriel91/ssh_cfg/actions/workflows/ci.yml)

Parses `~/.ssh/config` asynchronously.

```rust
use ssh_cfg::{SshConfigParser, SshOptionKey};
use tokio::runtime;

async fn parse_ssh_config() -> Result<(), Box<dyn std::error::Error>> {
    let ssh_config = SshConfigParser::parse_home().await?;

    // Print first host config
    if let Some((first_host, host_config)) = ssh_config.iter().next() {
        println!("Host: {}", first_host);

        // Print its configured SSH key if any
        if let Some(identity_file) = host_config.get(&SshOptionKey::IdentityFile) {
            println!("  {} {}", SshOptionKey::IdentityFile, identity_file);
        }
    }

    // Print all host configs
    println!();
    println!("{:#?}", ssh_config);

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rt = runtime::Builder::new_current_thread().build()?;
    rt.block_on(parse_ssh_config())
}
```

Currently values are stored as `String`s. Ideally we would parse them into a
strong data model.

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
