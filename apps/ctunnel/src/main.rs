use std::{collections::HashSet, fs, path::PathBuf, sync::Arc};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};

use ctunnel_core::{
    crypto::Ed25519Keypair,
    crypto::CryptoProvider,
    handshake::ServerPolicy,
    protocol::Ed25519PublicKey,
};
use ctunnel_crypto_sodium::SodiumCryptoProvider;
use ctunnel_net_tokio::{accept_tcp, connect_tcp};

#[derive(Parser)]
#[command(name = "ctunnel", version, about = "ctunnel CLI demo (Phase 5)")]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    // Run an echo server that accepts one client and echoes decrypted data frames back.
    Server {
        // Bind address, e.g. 127.0.0.1:9000
        #[arg(long)]
        bind: String,

        /// Server Ed25519 secret key file (64 bytes hex / 128 hex chars)
        #[arg(long)]
        server_key: PathBuf,

        /// Allowed client public key file (32 bytes hex / 64 hex chars). Can be repeated.
        #[arg(long)]
        allow_client: Vec<PathBuf>,
    },

    // Connect to server, send a message, print the echoed response.
    Client {
        // Server address, e.g. 127.0.0.1:9000
        #[arg(long)]
        connect: String,

        // Client Ed25519 secret key file (64 bytes hex / 128 hex chars)
        #[arg(long)]
        client_key: PathBuf,

        // Expected server public key file (32 bytes hex / 64 hex chars)
        #[arg(long)]
        expect_server: PathBuf,

        // Message to send
        #[arg(long)]
        msg: String,
    },

    // Generate an Ed25519 keypair
    Keygen {
        // Output directory
        #[arg(long)]
        out_dir: PathBuf,

        // Prefix for filenames (e.g. "server" -> server.key / server.pub)
        #[arg(long)]
        name: String,

        // Overwrite existing files
        #[arg(long, default_value_t = false)]
        force: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Command::Server { bind, server_key, allow_client } => {
            run_server(bind, server_key, allow_client).await
        }
        Command::Client { connect, client_key, expect_server, msg } => {
            run_client(connect, client_key, expect_server, msg).await
        }
        Command::Keygen { out_dir, name, force } => {
            run_keygen(out_dir, name, force).await
        }
    }
}

async fn run_server(bind: String, server_key: PathBuf, allow_client: Vec<PathBuf>) -> Result<()> {
    if allow_client.is_empty() {
        return Err(anyhow!("--allow-client is required at least once"));
    }

    let crypto = Arc::new(SodiumCryptoProvider::new());

    let server_id = load_ed25519_keypair(&server_key)?;
    let server_pk = Ed25519PublicKey(server_id.public);

    let mut allowed = HashSet::new();
    for p in allow_client {
        let pk = load_pubkey32(&p)?;
        allowed.insert(Ed25519PublicKey(pk));
    }
    let policy = ServerPolicy::new(allowed);

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .with_context(|| format!("failed to bind {bind}"))?;

    eprintln!("ctunnel server listening on {bind}");
    eprintln!("server public key: {}", hex::encode(server_pk.0));

    let (mut conn, peer) = accept_tcp(&listener, crypto, server_id, policy).await?;
    eprintln!("accepted secure connection from client pk={}", hex::encode(peer.0));

    // Simple echo loop (end when client disconnects/errors)
    loop {
        match conn.recv_data().await {
            Ok(msg) => {
                eprintln!("recv {} bytes", msg.len());
                conn.send_data(&msg).await?;
            }
            Err(e) => {
                eprintln!("connection ended: {e}");
                break;
            }
        }
    }

    Ok(())
}

async fn run_client(connect: String, client_key: PathBuf, expect_server: PathBuf, msg: String) -> Result<()> {
    let crypto = Arc::new(SodiumCryptoProvider::new());

    let client_id = load_ed25519_keypair(&client_key)?;
    let expected_server_pk = Ed25519PublicKey(load_pubkey32(&expect_server)?);

    let mut conn = connect_tcp(&connect, crypto, client_id, expected_server_pk).await?;

    conn.send_data(msg.as_bytes()).await?;
    let echo = conn.recv_data().await?;
    println!("{}", String::from_utf8_lossy(&echo));

    Ok(())
}

async fn run_keygen(out_dir: PathBuf, name: String, force: bool) -> Result<()> {
    let crypto = SodiumCryptoProvider::new();

    let kp = crypto.ed25519_generate().await?;

    fs::create_dir_all(&out_dir)
        .with_context(|| format!("failed to create {}", out_dir.display()))?;

    let key_path = out_dir.join(format!("{name}.key"));
    let pub_path = out_dir.join(format!("{name}.pub"));

    if !force {
        if key_path.exists() || pub_path.exists() {
            return Err(anyhow!(
                "key files already exist (use --force to overwrite)"
            ));
        }
    }

    fs::write(&key_path, hex::encode(kp.secret))
        .with_context(|| format!("failed to write {}", key_path.display()))?;
    fs::write(&pub_path, hex::encode(kp.public))
        .with_context(|| format!("failed to write {}", pub_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;
        fs::set_permissions(&pub_path, fs::Permissions::from_mode(0o644))?;
    }

    println!("generated:");
    println!("  secret: {}", key_path.display());
    println!("  public: {}", pub_path.display());

    Ok(())
}

fn load_hex_bytes(path: &PathBuf, expected_len: usize) -> Result<Vec<u8>> {
    let s = fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let s = s.trim();

    let bytes = hex::decode(s).with_context(|| format!("invalid hex in {}", path.display()))?;
    if bytes.len() != expected_len {
        return Err(anyhow!(
            "wrong length in {}: got {} bytes, expected {}",
            path.display(),
            bytes.len(),
            expected_len
        ));
    }
    Ok(bytes)
}

fn load_ed25519_keypair(path: &PathBuf) -> Result<Ed25519Keypair> {
    let sk = load_hex_bytes(path, 64)?;
    let mut secret = [0u8; 64];
    secret.copy_from_slice(&sk);

    // Public key must be loaded from the .pub file explicitly
    let pub_path = path.with_extension("pub");
    let pk = load_pubkey32(&pub_path)?;

    Ok(Ed25519Keypair {
        public: pk,
        secret,
    })
}

fn load_pubkey32(path: &PathBuf) -> Result<[u8; 32]> {
    let pk = load_hex_bytes(path, 32)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&pk);
    Ok(out)
}