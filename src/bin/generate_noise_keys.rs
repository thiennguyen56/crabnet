//! Generate local Noise-IK static keypairs for the namespace lab.

use std::fs;

use snow::{params::NoiseParams, Builder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
  let params: NoiseParams = "Noise_IK_25519_ChaChaPoly_BLAKE2s".parse()?;
  for (private_path, public_path) in [
    ("config/client/client.key", "config/client/client.pub"),
    ("config/server/server.key", "config/server/server.pub"),
  ] {
    let keypair = Builder::new(params.clone()).generate_keypair()?;
    fs::write(private_path, encode_hex(&keypair.private))?;
    #[cfg(unix)]
    {
      use std::os::unix::fs::PermissionsExt;
      fs::set_permissions(private_path, fs::Permissions::from_mode(0o600))?;
    }
    fs::write(public_path, encode_hex(&keypair.public))?;
    println!("generated {private_path} and {public_path}");
  }
  Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
  bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
