use std::{collections::HashSet, fs, path::PathBuf, sync::Arc};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};

use anchor::{AnchorConn, AnchorListener, Identity, PublicKey, TrustPolicy};


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

        // Server Ed25519 secret key file (64 bytes hex / 128 hex chars)
        #[arg(long)]
        server_key: PathBuf,

        // Allowed client public key file (32 bytes hex / 64 hex chars). Can be repeated.
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

fn read_pubkey(path: &PathBuf) -> Result<[u8; 32]> {
    let s = std::fs::read_to_string(path)?;
    let bytes = hex::decode(s.trim())?;
    if bytes.len() != 32 {
        return Err(anyhow!("invalid public key length in {}", path.display()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

async fn run_server(bind: String, server_key: PathBuf, allow_client: Vec<PathBuf>) -> Result<()> {
    if allow_client.is_empty() {
        return Err(anyhow!("--allow-client must be provided at least once"));
    }

    let identity = Identity::from_files(
        &server_key,
        server_key.with_extension("pub"),
    )?;

    let mut allowed = HashSet::new();
    for p in allow_client {
        let pk_bytes = read_pubkey(&p)?;
        allowed.insert(PublicKey(pk_bytes));
    }

    let listener = anchor::listen(
        &bind,
        identity,
        TrustPolicy::AllowList(allowed),
    )
    .await?;

    println!("ANCHOR server listening on {}", bind);
    println!(
        "server public key: {}",
        hex::encode(listener.local_addr()?.ip().to_string())
    );

    let mut conn = listener.accept().await?;
    println!(
        "accepted secure connection from client pk={}",
        hex::encode(conn.peer_identity().0)
    );

    loop {
        match conn.recv().await {
            Ok(msg) => {
                println!("recv {} bytes", msg.len());
                conn.send(&msg).await?;
            }
            Err(e) => {
                println!("connection ended: {e}");
                break;
            }
        }
    }

    Ok(())
}

async fn run_client(
    connect: String,
    client_key: PathBuf,
    expect_server: PathBuf,
    msg: String,
) -> Result<()> {
    let identity = Identity::from_files(
        &client_key,
        client_key.with_extension("pub"),
    )?;

    let server_pk = read_pubkey(&expect_server)?;

    let mut conn = anchor::connect(
        &connect,
        identity,
        TrustPolicy::Pinned(PublicKey(server_pk)),
    )
    .await?;

    conn.send(msg.as_bytes()).await?;
    let echo = conn.recv().await?;

    println!("{}", String::from_utf8_lossy(&echo));
    Ok(())
}

async fn run_keygen(out_dir: PathBuf, name: String, force: bool) -> Result<()> {
    let id = Identity::generate().await?;

    std::fs::create_dir_all(&out_dir)?;

    let key_path = out_dir.join(format!("{name}.key"));
    let pub_path = out_dir.join(format!("{name}.pub"));

    if !force && (key_path.exists() || pub_path.exists()) {
        return Err(anyhow!("key files already exist (use --force to overwrite)"));
    }

    std::fs::write(&key_path, hex::encode(id.secret_key))?;
    std::fs::write(&pub_path, hex::encode(id.public_key.0))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
        std::fs::set_permissions(&pub_path, std::fs::Permissions::from_mode(0o644))?;
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