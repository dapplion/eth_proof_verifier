//! A standalone verifier for EIP-8025 execution proofs.
//!
//! A beacon node points `--proof-engine-endpoint` at this process and asks it whether a gossiped
//! execution proof verifies. It holds no key, speaks no gossip, keeps no chain state, and produces
//! nothing.

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use clap::Parser;
use eth_proof_verifier::{api, registry::Registry};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "eth_proof_verifier", version, about, long_about = None)]
struct Config {
    /// Address to serve on.
    #[arg(long, default_value = "127.0.0.1:8025")]
    listen_address: SocketAddr,
    /// Proof types to serve in addition to, or in place of, the compiled-in ones. Entries are
    /// matched by proof type number.
    #[arg(long, value_name = "FILE")]
    proof_types: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let registry = Registry::load(config.proof_types.as_deref())?;
    for spec in registry.specs() {
        info!("Serving proof type {spec}");
    }

    let listener = tokio::net::TcpListener::bind(config.listen_address).await?;
    info!(
        address = %listener.local_addr()?,
        "Verifying execution proofs"
    );

    axum::serve(listener, api::router(Arc::new(registry)))
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}

async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
    info!("Shutting down");
}
