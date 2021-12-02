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
