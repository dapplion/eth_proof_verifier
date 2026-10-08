//! A beacon node points `--proof-engine-endpoint` here. No key, no gossip, no chain state.

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use clap::Parser;
use eth_proof_verifier::{api, registry::Registry};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "eth_proof_verifier", version, about, long_about = None)]
struct Config {
    /// Address to serve on.
    #[arg(long, default_value = "127.0.0.1:8025")]
    listen_address: SocketAddr,
    /// Proof types to add to, or replace, the compiled-in ones. Matched by proof type number.
    #[arg(long, value_name = "FILE")]
    proof_types: Option<PathBuf>,
    /// Lighthouse's `--proof-engine` file, served instead of the compiled-in proof types.
    #[arg(long, value_name = "FILE", conflicts_with = "proof_types")]
    proof_engine: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
    let config = Config::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // `Display`, not the `Debug` a `Result` from `main` prints: that drops the proof type and path.
    if let Err(error) = serve(config).await {
        error!("{error}");
        std::process::exit(1);
    }
}

async fn serve(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    let registry = match &config.proof_engine {
        Some(path) => Registry::load_proof_engine(path)?,
        None => Registry::load(config.proof_types.as_deref())?,
    };
    for spec in registry.specs() {
        info!("Serving proof type {spec}");
    }

    let listener = tokio::net::TcpListener::bind(config.listen_address).await?;
    info!(address = %listener.local_addr()?, "Verifying execution proofs");

    axum::serve(listener, api::router(Arc::new(registry))).await?;
    Ok(())
}
