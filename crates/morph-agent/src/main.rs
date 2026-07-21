use std::{
    collections::BTreeSet,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use k256::ecdsa::SigningKey;
use morph_agent::{
    AgentConfig, AgentService, AssetKind, CredentialService, DurableStore, FiberRpcClient,
    RgbppAsset, serve,
};

const MAX_ASSET_CATALOG_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Parser)]
#[command(name = "morph-agent", about = "Morph-owned RGB++ Agent/Fiber sidecar")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)] // Parsed once at process start; boxing every CLI field adds noise.
enum Command {
    /// Generate a Biscuit root key for MORPH_AGENT_BISCUIT_PRIVATE_KEY.
    GenerateKey,
    /// Generate a secp256k1 key for MORPH_AGENT_RECEIPT_PRIVATE_KEY.
    GenerateReceiptKey,
    /// Run the x402 gateway/facilitator against an unmodified Fiber node.
    Serve {
        #[arg(long, default_value = "127.0.0.1:4620")]
        listen: SocketAddr,
        #[arg(long, default_value = "http://127.0.0.1:8227")]
        fiber_rpc: String,
        #[arg(long, env = "MORPH_AGENT_FIBER_BEARER_TOKEN", hide_env_values = true)]
        fiber_bearer_token: Option<String>,
        #[arg(long, default_value = "./morph-agent.db")]
        store: PathBuf,
        #[arg(long, env = "MORPH_AGENT_BISCUIT_PRIVATE_KEY", hide_env_values = true)]
        biscuit_private_key: String,
        /// secp256k1 key used to sign canonical terminal settlement receipts.
        #[arg(long, env = "MORPH_AGENT_RECEIPT_PRIVATE_KEY", hide_env_values = true)]
        receipt_private_key: String,
        #[arg(long)]
        payee: String,
        /// Morph identity allowed to sign outgoing `/v1/pay` requests.
        #[arg(long)]
        outgoing_payer: Option<String>,
        /// Maximum routing fee for one outgoing payment, in asset base units.
        /// Required when --outgoing-payer is set.
        #[arg(long)]
        outgoing_max_fee_amount: Option<u128>,
        /// Maximum outgoing Fiber payment timeout accepted from callers.
        #[arg(long, default_value_t = 60)]
        outgoing_payment_timeout_seconds: u64,
        #[arg(long, default_value = "Fibd")]
        currency: String,
        #[arg(long)]
        ckb_network_id: Option<String>,
        /// JSON array of configured CKB/RGB++ assets. Defaults to CKB only.
        #[arg(long)]
        asset_catalog: Option<PathBuf>,
        /// Operator-verified RGB++ proof commitment; repeat for multiple proofs.
        #[arg(long = "verified-rgbpp-proof-commitment")]
        verified_rgbpp_proof_commitments: Vec<String>,
        #[arg(long, default_value_t = 3600)]
        credential_ttl_seconds: u64,
        /// Fixed upstream used by the paid `/gateway/*` reverse proxy.
        #[arg(long)]
        upstream_base_url: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::GenerateKey => {
            let service = CredentialService::generate();
            println!("private_key={}", service.private_key());
            println!("public_key={}", service.public_key());
        }
        Command::GenerateReceiptKey => {
            let key = loop {
                let candidate = morph_agent::random_byte32();
                if let Ok(key) = SigningKey::from_slice(&candidate) {
                    break key;
                }
            };
            println!("private_key=0x{}", hex::encode(key.to_bytes()));
            println!(
                "public_key=0x{}",
                hex::encode(key.verifying_key().to_encoded_point(true).as_bytes())
            );
        }
        Command::Serve {
            listen,
            fiber_rpc,
            fiber_bearer_token,
            store,
            biscuit_private_key,
            receipt_private_key,
            payee,
            outgoing_payer,
            outgoing_max_fee_amount,
            outgoing_payment_timeout_seconds,
            currency,
            ckb_network_id,
            asset_catalog,
            verified_rgbpp_proof_commitments,
            credential_ttl_seconds,
            upstream_base_url,
        } => {
            let credentials = CredentialService::from_private_key(&biscuit_private_key)
                .context("invalid MORPH_AGENT_BISCUIT_PRIVATE_KEY")?;
            let receipt_signing_key = parse_receipt_signing_key(&receipt_private_key)?;
            let durable_store = Arc::new(
                DurableStore::open(store, credentials.store_key())
                    .context("failed to open encrypted Morph Agent store")?,
            );
            let assets = match asset_catalog {
                Some(path) => read_asset_catalog(&path)?,
                None => vec![RgbppAsset {
                    kind: AssetKind::Ckb,
                    ckb_network_id: ckb_network_id
                        .context("--ckb-network-id is required when --asset-catalog is absent")?,
                    type_script_hash: None,
                    type_script: None,
                    bitcoin_network: None,
                    binding_code_hash: None,
                    symbol: "CKB".to_string(),
                    decimals: 8,
                }],
            };
            let fiber = FiberRpcClient::new(&fiber_rpc, fiber_bearer_token)
                .context("invalid Fiber RPC configuration")?;
            let service = Arc::new(
                AgentService::new(
                    AgentConfig {
                        payee,
                        outgoing_payer,
                        outgoing_max_fee_amount,
                        outgoing_payment_timeout_seconds,
                        currency,
                        supported_assets: assets,
                        verified_rgbpp_proof_commitments: verified_rgbpp_proof_commitments
                            .into_iter()
                            .collect::<BTreeSet<_>>(),
                        default_credential_ttl_seconds: credential_ttl_seconds,
                        upstream_base_url,
                    },
                    fiber,
                    durable_store,
                    credentials,
                    receipt_signing_key,
                )
                .context("invalid Morph Agent configuration")?,
            );
            let listener = tokio::net::TcpListener::bind(listen)
                .await
                .with_context(|| format!("failed to listen on {listen}"))?;
            serve(service, listener).await?;
        }
    }
    Ok(())
}

fn parse_receipt_signing_key(value: &str) -> Result<SigningKey> {
    let raw = hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .context("MORPH_AGENT_RECEIPT_PRIVATE_KEY must be hexadecimal")?;
    ensure!(
        raw.len() == 32,
        "MORPH_AGENT_RECEIPT_PRIVATE_KEY must be 32 bytes"
    );
    SigningKey::from_slice(&raw).context("invalid MORPH_AGENT_RECEIPT_PRIVATE_KEY")
}

fn read_asset_catalog(path: &Path) -> Result<Vec<RgbppAsset>> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("failed to stat asset catalog {}", path.display()))?;
    ensure!(
        metadata.len() <= MAX_ASSET_CATALOG_BYTES,
        "asset catalog exceeds 1 MiB"
    );
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read asset catalog {}", path.display()))?;
    let assets: Vec<RgbppAsset> =
        serde_json::from_slice(&bytes).context("asset catalog must be a JSON asset array")?;
    ensure!(!assets.is_empty(), "asset catalog must not be empty");
    Ok(assets)
}
