use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use ckb_jsonrpc_types::{
    BlockView, CellWithStatus, OutPoint as JsonOutPoint, Status, Transaction,
    TransactionWithStatusResponse,
};
use ckb_types::H256;
use reqwest::blocking::Client;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

#[derive(Debug, Clone)]
pub struct CkbRpcClient {
    url: String,
    client: Client,
}

#[derive(Debug, Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HeaderView {
    pub hash: String,
    pub number: String,
    pub parent_hash: String,
    pub timestamp: String,
    pub epoch: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChainInfo {
    pub chain: String,
    pub median_time: String,
    pub epoch: String,
    pub is_initial_block_download: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LocalNodeInfo {
    pub active: bool,
    pub node_id: String,
    pub connections: String,
}

#[derive(Debug, Clone)]
pub struct DevnetStatus {
    pub tip: HeaderView,
    pub chain: ChainInfo,
    pub node: LocalNodeInfo,
}

impl CkbRpcClient {
    pub fn new(url: impl Into<String>) -> Result<Self> {
        let url = url.into();
        let client = Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .context("failed to build HTTP client")?;
        Ok(Self { url, client })
    }

    pub fn tip_header(&self) -> Result<HeaderView> {
        self.call("get_tip_header", json!([]))
    }

    pub fn chain_info(&self) -> Result<ChainInfo> {
        self.call("get_blockchain_info", json!([]))
    }

    pub fn local_node_info(&self) -> Result<LocalNodeInfo> {
        self.call("local_node_info", json!([]))
    }

    pub fn status(&self) -> Result<DevnetStatus> {
        Ok(DevnetStatus {
            tip: self.tip_header()?,
            chain: self.chain_info()?,
            node: self.local_node_info()?,
        })
    }

    pub fn generate_block(&self) -> Result<String> {
        self.call("generate_block", json!([])).with_context(
            || "generate_block failed; ensure the node exposes CKB integration-test RPC methods",
        )
    }

    pub fn block_by_number(&self, number: u64) -> Result<Option<BlockView>> {
        self.call(
            "get_block_by_number",
            json!([format_quantity(number), format_quantity(2), false]),
        )
    }

    pub fn live_cell(&self, out_point: JsonOutPoint, with_data: bool) -> Result<CellWithStatus> {
        self.call("get_live_cell", json!([out_point, with_data, true]))
    }

    pub fn send_transaction(&self, transaction: Transaction) -> Result<H256> {
        self.call("send_transaction", json!([transaction, "passthrough"]))
    }

    pub fn transaction(&self, tx_hash: H256) -> Result<TransactionWithStatusResponse> {
        self.call(
            "get_transaction",
            json!([tx_hash, format_quantity(2), null]),
        )
    }

    pub fn wait_transaction_committed(
        &self,
        tx_hash: H256,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Result<TransactionWithStatusResponse> {
        let started = Instant::now();
        loop {
            let tx = self.transaction(tx_hash.clone())?;
            match tx.tx_status.status {
                Status::Committed => return Ok(tx),
                Status::Rejected => {
                    bail!(
                        "transaction {tx_hash:#x} rejected: {}",
                        tx.tx_status
                            .reason
                            .as_deref()
                            .unwrap_or("node did not report a rejection reason")
                    );
                }
                _ => {}
            }
            if started.elapsed() >= timeout {
                bail!(
                    "timed out waiting for transaction {tx_hash:#x}; current status is {:?}",
                    tx.tx_status.status
                );
            }
            std::thread::sleep(poll_interval);
        }
    }

    pub fn wait_for_tip(
        &self,
        min_number: u64,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Result<HeaderView> {
        let started = Instant::now();
        loop {
            let tip = self.tip_header()?;
            if tip.number_value()? >= min_number {
                return Ok(tip);
            }
            if started.elapsed() >= timeout {
                bail!(
                    "timed out waiting for tip >= {min_number}; current tip is {}",
                    tip.number_value()?
                );
            }
            std::thread::sleep(poll_interval);
        }
    }

    fn call<T: DeserializeOwned>(&self, method: &str, params: Value) -> Result<T> {
        let request = json!({
            "id": 1,
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        });
        let response = self
            .client
            .post(&self.url)
            .json(&request)
            .send()
            .with_context(|| format!("failed to call CKB RPC at {}", self.url))?;
        let status = response.status();
        let body = response
            .text()
            .context("failed to read CKB RPC response body")?;
        if !status.is_success() {
            bail!("CKB RPC HTTP error {status}: {body}");
        }
        let response: RpcResponse<T> = serde_json::from_str(&body)
            .with_context(|| format!("invalid JSON-RPC response for method {method}: {body}"))?;
        if let Some(error) = response.error {
            bail!(
                "CKB RPC error {} on {method}: {}",
                error.code,
                error.message
            );
        }
        response
            .result
            .ok_or_else(|| anyhow!("CKB RPC response for {method} has no result"))
    }
}

impl HeaderView {
    pub fn number_value(&self) -> Result<u64> {
        parse_quantity(&self.number)
    }

    pub fn timestamp_value(&self) -> Result<u64> {
        parse_quantity(&self.timestamp)
    }
}

impl ChainInfo {
    pub fn median_time_value(&self) -> Result<u64> {
        parse_quantity(&self.median_time)
    }
}

impl LocalNodeInfo {
    pub fn connection_count(&self) -> Result<u64> {
        parse_quantity(&self.connections)
    }
}

fn parse_quantity(value: &str) -> Result<u64> {
    let hex = value
        .strip_prefix("0x")
        .ok_or_else(|| anyhow!("quantity is not 0x-prefixed: {value}"))?;
    u64::from_str_radix(hex, 16).with_context(|| format!("invalid hex quantity: {value}"))
}

fn format_quantity(value: u64) -> String {
    format!("0x{value:x}")
}
