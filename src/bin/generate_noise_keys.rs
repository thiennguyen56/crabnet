//! Generate local Noise-IK static keypairs for the namespace lab.

use std::fs;

use clap::Parser;

use snow::{params::NoiseParams, Builder};

/// Output locations for a local Noise-IK client and server keypair.
#[derive(Debug, Parser)]
struct Args {
  /// Client private-key output path.
  #[arg(long, default_value = "config/client/client.key")]
  client_private: String,
  /// Client public-key output path.
  #[arg(long, default_value = "config/client/client.pub")]
  client_public: String,
  /// Server private-key output path.
  #[arg(long, default_value = "config/server/server.key")]
  server_private: String,
  /// Server public-key output path.
  #[arg(long, default_value = "config/server/server.pub")]
  server_public: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
  let args = Args::parse();
  let params: NoiseParams = "Noise_IK_25519_ChaChaPoly_BLAKE2s".parse()?;
  for (private_path, public_path) in [
    (args.client_private, args.client_public),
    (args.server_private, args.server_public),
  ] {
    let keypair = Builder::new(params.clone()).generate_keypair()?;
    fs::write(&private_path, encode_hex(&keypair.private))?;
    #[cfg(unix)]
    {
      use std::os::unix::fs::PermissionsExt;
      fs::set_permissions(&private_path, fs::Permissions::from_mode(0o600))?;
    }
    fs::write(&public_path, encode_hex(&keypair.public))?;
    println!("generated {private_path} and {public_path}");
  }
  Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
  bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
