use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use anyhow::{Context, Result, anyhow, ensure};
use morph_core::*;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::rpc::CkbRpcClient;

const STATE_FILE_VERSION: u16 = 1;
const MAX_REQUEST_BODY_BYTES: usize = 1_048_576;
const MAX_REQUEST_LINE_BYTES: usize = 8 * 1024;
const MAX_REQUEST_HEADER_BYTES: usize = 64 * 1024;
const REQUEST_IO_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_EVENTS: usize = 128;
const EVENT_STREAM_POLL_INTERVAL: Duration = Duration::from_millis(1_000);
const EVENT_STREAM_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);

pub struct HubServeOptions {
    pub listen: String,
    pub state_path: PathBuf,
    pub pubkey: String,
    pub network: MorphNetwork,
    pub ckb_rpc_url: Option<String>,
    pub ui_dir: PathBuf,
    pub auth_token: Option<String>,
    pub allow_state_restore: bool,
    pub cors_origin: Option<String>,
}

struct HubServer {
    store: Arc<Mutex<HubStore>>,
    ui_dir: PathBuf,
    ckb_rpc_url: Option<String>,
    auth_token: Option<String>,
    allow_state_restore: bool,
    cors_origin: Option<String>,
}

#[derive(Clone)]
struct HubStore {
    path: PathBuf,
    state: HubRuntimeState,
    next_event_id: u64,
}

#[derive(Clone)]
struct HubRuntimeState {
    pubkey: String,
    peer_pubkeys: BTreeMap<Bytes32, String>,
    node: MorphNodeState,
    events: Vec<HubEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedHubState {
    version: u16,
    pubkey: String,
    network: MorphNetwork,
    peers: Vec<PersistedPeer>,
    channels: Vec<PersistedChannel>,
    factories: Vec<PersistedFactory>,
    invoices: Vec<StoredMorphInvoice>,
    completed_flows: Vec<MorphBusinessFlow>,
    events: Vec<HubEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedPeer {
    pubkey: String,
    alias: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedChannel {
    channel_id: String,
    counterparty_pubkey: String,
    funding_epoch: u64,
    funding_context_id: String,
    state_number: u64,
    phase: Phase,
    balances: Vec<MorphAssetBalance>,
    sponsor_budget: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedFactory {
    factory_id: String,
    participant_pubkeys: Vec<String>,
    update_number: u64,
    reserve_balances: Vec<MorphAssetBalance>,
    materialised_child_channels: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HubEvent {
    id: u64,
    severity: EventSeverity,
    event: String,
    subject_id: Option<Bytes32>,
    message: String,
    created_at_unix: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum EventSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

struct HttpResponse {
    status: u16,
    reason: &'static str,
    content_type: &'static str,
    body: Vec<u8>,
}

impl HttpRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }
}

#[derive(Debug, Deserialize)]
struct CreateInvoiceRequest {
    amount: String,
    description: String,
    payment_preimage: Option<String>,
    payment_hash: Option<String>,
    expiry_secs: u64,
    channel_id: Option<String>,
    asset: Option<AssetRequest>,
}

#[derive(Debug, Deserialize)]
struct DecodeInvoiceRequest {
    encoded_invoice: String,
}

#[derive(Debug, Deserialize)]
struct SettleInvoiceRequest {
    payment_preimage: String,
}

#[derive(Debug, Deserialize)]
struct ConnectPeerRequest {
    pubkey: String,
    alias: String,
}

#[derive(Debug, Deserialize)]
struct OpenChannelRequest {
    channel_id: String,
    counterparty_pubkey: String,
    counterparty_alias: Option<String>,
    funding_context_id: String,
    local: String,
    remote: String,
    pending: Option<String>,
    sponsor_budget: u64,
    asset: Option<AssetRequest>,
}

#[derive(Debug, Deserialize)]
struct SpliceChannelRequest {
    new_funding_epoch: u64,
    new_funding_context_id: String,
}

#[derive(Debug, Deserialize)]
struct PublishStateRequest {
    funding_context_id: String,
    state_number: u64,
}

#[derive(Debug, Deserialize)]
struct OpenFactoryRequest {
    factory_id: String,
    participant_pubkeys: Vec<String>,
    reserve: String,
    asset: Option<AssetRequest>,
}

#[derive(Debug, Deserialize)]
struct AdvanceFactoryRequest {
    new_update_number: u64,
}

#[derive(Debug, Deserialize)]
struct MaterialiseChildRequest {
    child_channel_id: String,
    counterparty_pubkey: String,
    counterparty_alias: Option<String>,
    funding_context_id: String,
    local: String,
    remote: String,
    pending: Option<String>,
    sponsor_budget: u64,
    asset: Option<AssetRequest>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum AssetRequest {
    Ckb,
    Xudt { type_hash: String },
}

#[derive(Serialize)]
struct HubView {
    pubkey: String,
    node_id: String,
    network: &'static str,
    state_path: String,
    rpc: RpcView,
    security: HubSecurityView,
    provenance: RecordProvenanceView,
    peers: Vec<PeerView>,
    channels: Vec<ChannelView>,
    invoices: Vec<InvoiceView>,
    factories: Vec<FactoryView>,
    events: Vec<EventView>,
    required_flows: Vec<&'static str>,
    completed_flows: Vec<&'static str>,
    missing_flows: Vec<&'static str>,
}

#[derive(Serialize)]
struct HubSecurityView {
    auth_required: bool,
    state_restore_enabled: bool,
    cors_origin: Option<String>,
}

#[derive(Serialize, Clone, Copy)]
struct RecordProvenanceView {
    source: &'static str,
    chain_status: &'static str,
    label: &'static str,
    message: &'static str,
}

#[derive(Serialize)]
struct RpcView {
    status: &'static str,
    url: Option<String>,
    tip_height: Option<u64>,
    chain: Option<String>,
    message: Option<String>,
}

#[derive(Serialize)]
struct PeerView {
    pubkey: String,
    node_id: String,
    alias: String,
    provenance: RecordProvenanceView,
}

#[derive(Serialize)]
struct ChannelView {
    channel_id: String,
    counterparty_pubkey: String,
    counterparty_node_id: String,
    funding_epoch: u64,
    funding_context_id: String,
    state_number: u64,
    phase: &'static str,
    balances: Vec<BalanceView>,
    sponsor_budget: u64,
    provenance: RecordProvenanceView,
}

#[derive(Serialize)]
struct BalanceView {
    asset: AssetView,
    local: String,
    remote: String,
    pending: String,
}

#[derive(Serialize)]
struct InvoiceView {
    invoice_id: String,
    encoded_invoice: String,
    status: &'static str,
    network: &'static str,
    payee_pubkey: Option<String>,
    payee_node_id: String,
    channel_id: Option<String>,
    asset: AssetView,
    amount: String,
    created_at_unix: u64,
    expires_at_unix: u64,
    payment_hash: String,
    description: String,
    received_at_unix: Option<u64>,
    paid_at_unix: Option<u64>,
    cancelled_at_unix: Option<u64>,
    provenance: RecordProvenanceView,
}

#[derive(Serialize)]
struct FactoryView {
    factory_id: String,
    participant_pubkeys: Vec<String>,
    participant_node_ids: Vec<String>,
    update_number: u64,
    reserve_balances: Vec<BalanceView>,
    materialised_child_channels: Vec<String>,
    provenance: RecordProvenanceView,
}

#[derive(Serialize)]
struct EventView {
    id: u64,
    severity: EventSeverity,
    event: String,
    subject_id: Option<String>,
    message: String,
    created_at_unix: u64,
    provenance: RecordProvenanceView,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum AssetView {
    Ckb,
    Xudt { type_hash: String },
}

fn local_state_provenance() -> RecordProvenanceView {
    RecordProvenanceView {
        source: "hub_state_file",
        chain_status: "not_chain_verified",
        label: "Local state",
        message: "Recorded in the Morph Hub state file; this is not CKB devnet confirmation.",
    }
}

fn normalise_optional_secret(value: Option<String>) -> Option<String> {
    value
        .map(|raw| raw.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn normalise_cors_origin(value: Option<String>) -> Result<Option<String>> {
    let Some(origin) = value.map(|raw| raw.trim().to_string()) else {
        return Ok(None);
    };
    if origin.is_empty() {
        return Ok(None);
    }
    ensure!(origin != "*", "--cors-origin must not be wildcard '*'");
    ensure!(
        origin.starts_with("http://") || origin.starts_with("https://"),
        "--cors-origin must be an http:// or https:// origin"
    );
    Ok(Some(origin))
}

fn listen_is_loopback(listen: &str) -> bool {
    listen_host(listen)
        .is_some_and(|host| host == "localhost" || host == "127.0.0.1" || host == "::1")
}

fn listen_host(listen: &str) -> Option<String> {
    let listen = listen.trim();
    if listen.is_empty() {
        return None;
    }
    if let Some(rest) = listen.strip_prefix('[') {
        let (host, _) = rest.split_once(']')?;
        return Some(host.to_string());
    }
    let (host, _) = listen.rsplit_once(':')?;
    Some(host.to_string())
}

pub fn serve(options: HubServeOptions) -> Result<()> {
    let auth_token = normalise_optional_secret(options.auth_token);
    let cors_origin = normalise_cors_origin(options.cors_origin)?;
    ensure!(
        listen_is_loopback(&options.listen) || auth_token.is_some(),
        "serving Morph Hub on a non-loopback address requires --auth-token or MORPH_HUB_AUTH_TOKEN"
    );
    let listener = TcpListener::bind(&options.listen)
        .with_context(|| format!("failed to bind Morph hub to {}", options.listen))?;
    let store = HubStore::load_or_create(options.state_path, &options.pubkey, options.network)?;
    let server = Arc::new(HubServer {
        store: Arc::new(Mutex::new(store)),
        ui_dir: options.ui_dir,
        ckb_rpc_url: options.ckb_rpc_url,
        auth_token,
        allow_state_restore: options.allow_state_restore,
        cors_origin,
    });

    println!("morph_hub_listen=http://{}", options.listen);
    println!(
        "morph_hub_state={}",
        server.store.lock().unwrap().path.display()
    );
    println!("morph_hub_ui={}", server.ui_dir.display());
    println!(
        "morph_hub_auth={}",
        if server.auth_token.is_some() {
            "required"
        } else {
            "loopback"
        }
    );
    println!(
        "morph_hub_state_restore={}",
        if server.allow_state_restore {
            "enabled"
        } else {
            "disabled"
        }
    );
    if let Some(origin) = &server.cors_origin {
        println!("morph_hub_cors_origin={origin}");
    }

    for stream in listener.incoming() {
        let stream = stream.context("failed to accept Morph hub connection")?;
        let server = Arc::clone(&server);
        thread::spawn(move || {
            if let Err(err) = handle_connection(stream, &server) {
                eprintln!("morph hub request failed: {err:#}");
            }
        });
    }
    Ok(())
}

impl HubStore {
    fn load_or_create(path: PathBuf, pubkey: &str, network: MorphNetwork) -> Result<Self> {
        let requested_pubkey = canonical_pubkey(pubkey)?;
        let state = if path.exists() {
            let raw = fs::read_to_string(&path)
                .with_context(|| format!("failed to read hub state {}", path.display()))?;
            let persisted: PersistedHubState = serde_json::from_str(&raw)
                .with_context(|| format!("failed to parse hub state {}", path.display()))?;
            HubRuntimeState::from_persisted(persisted)?
        } else {
            let node_id = node_id_from_pubkey(&requested_pubkey)?;
            HubRuntimeState {
                pubkey: requested_pubkey.clone(),
                peer_pubkeys: BTreeMap::new(),
                node: MorphNodeState::new(node_id, network)?,
                events: Vec::new(),
            }
        };
        ensure!(
            state.pubkey == requested_pubkey,
            "hub state pubkey {} does not match --pubkey {}",
            state.pubkey,
            requested_pubkey
        );
        ensure!(
            state.node.network == network,
            "hub state network {} does not match --network {}",
            network_label(state.node.network),
            network_label(network)
        );
        let next_event_id = state
            .events
            .iter()
            .map(|event| event.id)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        let store = Self {
            path,
            state,
            next_event_id,
        };
        store.persist()?;
        Ok(store)
    }

    fn replace(&mut self, persisted: PersistedHubState) -> Result<()> {
        let mut candidate = self.clone();
        candidate.state = HubRuntimeState::from_persisted(persisted)?;
        ensure!(
            candidate.state.pubkey == self.state.pubkey,
            "restored hub state pubkey {} does not match running pubkey {}",
            candidate.state.pubkey,
            self.state.pubkey
        );
        ensure!(
            candidate.state.node.network == self.state.node.network,
            "restored hub state network {} does not match running network {}",
            network_label(candidate.state.node.network),
            network_label(self.state.node.network)
        );
        candidate.push_event(
            EventSeverity::Warning,
            "state_restored",
            None,
            "Hub state file was replaced through the API",
        )?;
        candidate.persist()?;
        *self = candidate;
        Ok(())
    }

    fn view(&self, rpc: RpcView, security: HubSecurityView) -> Result<HubView> {
        Ok(HubView {
            pubkey: self.state.pubkey.clone(),
            node_id: hex_prefixed(&self.state.node.node_id),
            network: network_label(self.state.node.network),
            state_path: self.path.display().to_string(),
            rpc,
            security,
            provenance: local_state_provenance(),
            peers: self
                .state
                .node
                .peers
                .values()
                .map(|peer| peer_view(peer, &self.state.peer_pubkeys))
                .collect::<Result<Vec<_>>>()?,
            channels: self
                .state
                .node
                .channels
                .values()
                .map(|channel| channel_view(channel, &self.state.peer_pubkeys))
                .collect::<Result<Vec<_>>>()?,
            invoices: self
                .state
                .node
                .invoices
                .records()
                .map(|invoice| invoice_view(invoice, self.state.node.node_id, &self.state.pubkey))
                .collect(),
            factories: self
                .state
                .node
                .factories
                .values()
                .map(|factory| {
                    factory_view(
                        factory,
                        self.state.node.node_id,
                        &self.state.pubkey,
                        &self.state.peer_pubkeys,
                    )
                })
                .collect::<Result<Vec<_>>>()?,
            events: self.state.events.iter().map(event_view).collect(),
            required_flows: MorphNodeState::required_business_flows()
                .iter()
                .copied()
                .map(flow_label)
                .collect(),
            completed_flows: self
                .state
                .node
                .completed_flows
                .iter()
                .copied()
                .map(flow_label)
                .collect(),
            missing_flows: self
                .state
                .node
                .missing_business_flows()
                .iter()
                .copied()
                .map(flow_label)
                .collect(),
        })
    }

    fn persisted(&self) -> Result<PersistedHubState> {
        Ok(PersistedHubState {
            version: STATE_FILE_VERSION,
            pubkey: self.state.pubkey.clone(),
            network: self.state.node.network,
            peers: self
                .state
                .node
                .peers
                .values()
                .map(|peer| persisted_peer(peer, &self.state.peer_pubkeys))
                .collect::<Result<Vec<_>>>()?,
            channels: self
                .state
                .node
                .channels
                .values()
                .map(|channel| persisted_channel(channel, &self.state.peer_pubkeys))
                .collect::<Result<Vec<_>>>()?,
            factories: self
                .state
                .node
                .factories
                .values()
                .map(|factory| {
                    persisted_factory(
                        factory,
                        self.state.node.node_id,
                        &self.state.pubkey,
                        &self.state.peer_pubkeys,
                    )
                })
                .collect::<Result<Vec<_>>>()?,
            invoices: self.state.node.invoices.records().cloned().collect(),
            completed_flows: self.state.node.completed_flows.iter().copied().collect(),
            events: self.state.events.clone(),
        })
    }

    fn persist(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let persisted = self.persisted()?;
        let data = serde_json::to_vec_pretty(&persisted)?;
        write_private_file_atomic(&self.path, &data)?;
        Ok(())
    }

    fn push_event(
        &mut self,
        severity: EventSeverity,
        event: impl Into<String>,
        subject_id: Option<Bytes32>,
        message: impl Into<String>,
    ) -> Result<()> {
        let id = self.next_event_id;
        self.next_event_id = self.next_event_id.saturating_add(1);
        self.state.events.insert(
            0,
            HubEvent {
                id,
                severity,
                event: event.into(),
                subject_id,
                message: message.into(),
                created_at_unix: now_unix()?,
            },
        );
        self.state.events.truncate(MAX_EVENTS);
        Ok(())
    }
}

impl HubRuntimeState {
    fn from_persisted(persisted: PersistedHubState) -> Result<Self> {
        ensure!(
            persisted.version == STATE_FILE_VERSION,
            "unsupported hub state version {}",
            persisted.version
        );
        let pubkey = canonical_pubkey(&persisted.pubkey)?;
        let mut peer_pubkeys = BTreeMap::new();
        let mut node = MorphNodeState::new(node_id_from_pubkey(&pubkey)?, persisted.network)?;
        for peer in persisted.peers {
            let pubkey = canonical_pubkey(&peer.pubkey)?;
            let node_id = node_id_from_pubkey(&pubkey)?;
            ensure!(
                node_id != node.node_id,
                "peer pubkey must not be local pubkey"
            );
            node.connect_peer(MorphPeer {
                node_id,
                alias: peer.alias,
            })?;
            peer_pubkeys.insert(node_id, pubkey);
        }
        for persisted_channel in persisted.channels {
            let counterparty_pubkey = canonical_pubkey(&persisted_channel.counterparty_pubkey)?;
            let counterparty_node_id = node_id_from_pubkey(&counterparty_pubkey)?;
            ensure!(
                counterparty_node_id != node.node_id,
                "channel counterparty pubkey must not be local pubkey"
            );
            if !node.peers.contains_key(&counterparty_node_id) {
                node.connect_peer(MorphPeer {
                    node_id: counterparty_node_id,
                    alias: counterparty_pubkey.clone(),
                })?;
            }
            peer_pubkeys.insert(counterparty_node_id, counterparty_pubkey);
            let channel = MorphChannelRecord {
                channel_id: parse_bytes32("channel_id", &persisted_channel.channel_id)?,
                counterparty_node_id,
                funding_epoch: persisted_channel.funding_epoch,
                funding_context_id: parse_bytes32(
                    "funding_context_id",
                    &persisted_channel.funding_context_id,
                )?,
                state_number: persisted_channel.state_number,
                phase: persisted_channel.phase,
                balances: persisted_channel.balances,
                sponsor_budget: persisted_channel.sponsor_budget,
            };
            node.open_channel(channel)?;
        }
        for persisted_factory in persisted.factories {
            let participant_pubkeys = persisted_factory
                .participant_pubkeys
                .iter()
                .map(|value| canonical_pubkey(value))
                .collect::<Result<Vec<_>>>()?;
            let participant_node_ids = participant_pubkeys
                .iter()
                .map(|participant_pubkey| node_id_from_pubkey(participant_pubkey))
                .collect::<Result<BTreeSet<_>>>()?;
            ensure!(
                participant_node_ids.len() == participant_pubkeys.len(),
                "factory participant pubkeys must be unique"
            );
            ensure!(
                participant_node_ids.contains(&node.node_id),
                "factory participant_pubkeys must include local pubkey"
            );
            for participant_pubkey in participant_pubkeys {
                let participant_node_id = node_id_from_pubkey(&participant_pubkey)?;
                if participant_node_id != node.node_id {
                    peer_pubkeys.insert(participant_node_id, participant_pubkey);
                }
            }
            let materialised_child_channels = persisted_factory
                .materialised_child_channels
                .iter()
                .map(|value| parse_bytes32("materialised_child_channel", value))
                .collect::<Result<BTreeSet<_>>>()?;
            let factory = MorphFactoryRecord {
                factory_id: parse_bytes32("factory_id", &persisted_factory.factory_id)?,
                participant_node_ids,
                update_number: persisted_factory.update_number,
                reserve_balances: persisted_factory.reserve_balances,
                materialised_child_channels,
            };
            node.open_factory(factory)?;
        }
        for invoice in persisted.invoices {
            node.invoices.insert_stored(invoice)?;
        }
        node.completed_flows = persisted.completed_flows.into_iter().collect();
        Ok(Self {
            pubkey,
            peer_pubkeys,
            node,
            events: persisted.events,
        })
    }
}

fn handle_connection(mut stream: TcpStream, server: &HubServer) -> Result<()> {
    stream
        .set_read_timeout(Some(REQUEST_IO_TIMEOUT))
        .context("failed to set Morph Hub request read timeout")?;
    stream
        .set_write_timeout(Some(REQUEST_IO_TIMEOUT))
        .context("failed to set Morph Hub response write timeout")?;
    let request = read_request(&mut stream)?;
    if request.method == "GET" && request.path == "/api/events" {
        server.stream_events(&request, &mut stream)?;
        return Ok(());
    }
    let response = server.route(request);
    write_response(&mut stream, response, server.cors_origin.as_deref())?;
    Ok(())
}

impl HubServer {
    fn route(&self, request: HttpRequest) -> HttpResponse {
        match self.route_result(request) {
            Ok(response) => response,
            Err(err) => json_response(400, "Bad Request", &json!({ "error": err.to_string() })),
        }
    }

    fn route_result(&self, request: HttpRequest) -> Result<HttpResponse> {
        if request.method == "OPTIONS" {
            return Ok(empty_response(204, "No Content"));
        }
        if request.path.starts_with("/api/") || request.path == "/api" {
            self.route_api(request)
        } else {
            self.route_static(request)
        }
    }

    fn route_api(&self, request: HttpRequest) -> Result<HttpResponse> {
        if let Some(response) = self.auth_failure_response(&request) {
            return Ok(response);
        }
        match (request.method.as_str(), request.path.as_str()) {
            ("GET", "/api/health") | ("GET", "/api/state") => self.state_response(),
            ("GET", "/api/state-file") => {
                let store = self.store.lock().unwrap();
                let persisted = store.persisted()?;
                Ok(json_response(200, "OK", &persisted))
            }
            ("PUT", "/api/state-file") => {
                if !self.allow_state_restore {
                    return Ok(json_response(
                        403,
                        "Forbidden",
                        &json!({
                            "error": "state restore is disabled; restart Morph Hub with --allow-state-restore to enable this write path"
                        }),
                    ));
                }
                let persisted: PersistedHubState = parse_body(&request.body)?;
                let mut store = self.store.lock().unwrap();
                store.replace(persisted)?;
                let view = store.view(self.rpc_view(), self.security_view())?;
                Ok(json_response(200, "OK", &view))
            }
            ("POST", "/api/peers") => self.mutate(|store| {
                let body: ConnectPeerRequest = parse_body(&request.body)?;
                let pubkey = canonical_pubkey(&body.pubkey)?;
                let node_id = node_id_from_pubkey(&pubkey)?;
                ensure!(
                    node_id != store.state.node.node_id,
                    "peer pubkey must not be local pubkey"
                );
                ensure!(
                    !body.alias.trim().is_empty(),
                    "peer alias must not be empty"
                );
                store.state.node.connect_peer(MorphPeer {
                    node_id,
                    alias: body.alias.trim().to_string(),
                })?;
                store.state.peer_pubkeys.insert(node_id, pubkey);
                store.push_event(
                    EventSeverity::Info,
                    "peer_connected",
                    Some(node_id),
                    "Peer added to the local node state",
                )?;
                Ok(())
            }),
            ("POST", "/api/invoices") => self.mutate(|store| {
                let body: CreateInvoiceRequest = parse_body(&request.body)?;
                ensure!(
                    body.expiry_secs > 0,
                    "expiry_secs must be greater than zero"
                );
                let created_at_unix = now_unix()?;
                let expires_at_unix = created_at_unix
                    .checked_add(body.expiry_secs)
                    .context("invoice expiry overflows u64")?;
                let payment_preimage = body
                    .payment_preimage
                    .as_deref()
                    .map(|value| parse_bytes32("payment_preimage", value))
                    .transpose()?;
                let payment_hash = body
                    .payment_hash
                    .as_deref()
                    .map(|value| parse_bytes32("payment_hash", value))
                    .transpose()?;
                ensure!(
                    payment_preimage.is_some() ^ payment_hash.is_some(),
                    "set exactly one of payment_preimage or payment_hash"
                );
                let channel_id = body
                    .channel_id
                    .as_deref()
                    .map(|value| parse_bytes32("channel_id", value))
                    .transpose()?;
                let stored = store.state.node.create_invoice(NewMorphInvoice {
                    network: store.state.node.network,
                    payee_node_id: store.state.node.node_id,
                    channel_id,
                    asset: parse_asset(body.asset)?,
                    amount: parse_amount("amount", &body.amount)?,
                    created_at_unix,
                    expires_at_unix,
                    payment_preimage,
                    payment_hash,
                    description: body.description.trim().to_string(),
                })?;
                store.push_event(
                    EventSeverity::Info,
                    "invoice_created",
                    Some(stored.invoice.invoice_id),
                    "Invoice created by morph-core",
                )?;
                Ok(())
            }),
            ("POST", "/api/invoices/decode") => self.mutate(|store| {
                let body: DecodeInvoiceRequest = parse_body(&request.body)?;
                let stored = store
                    .state
                    .node
                    .invoices
                    .insert_decoded(body.encoded_invoice.trim())?;
                store
                    .state
                    .node
                    .completed_flows
                    .insert(MorphBusinessFlow::InvoiceReceived);
                store.push_event(
                    EventSeverity::Info,
                    "invoice_decoded",
                    Some(stored.invoice.invoice_id),
                    "Invoice decoded and stored",
                )?;
                Ok(())
            }),
            ("POST", path) if path.starts_with("/api/invoices/") => {
                self.route_invoice_action(path, &request.body)
            }
            ("POST", "/api/channels") => self.mutate(|store| {
                let body: OpenChannelRequest = parse_body(&request.body)?;
                let counterparty_pubkey = canonical_pubkey(&body.counterparty_pubkey)?;
                let counterparty_node_id = node_id_from_pubkey(&counterparty_pubkey)?;
                ensure_peer(
                    &mut store.state,
                    &counterparty_pubkey,
                    counterparty_node_id,
                    body.counterparty_alias.as_deref(),
                )?;
                let channel = channel_from_request(
                    &body.channel_id,
                    counterparty_node_id,
                    &body.funding_context_id,
                    &body.local,
                    &body.remote,
                    body.pending.as_deref(),
                    body.sponsor_budget,
                    body.asset,
                )?;
                let channel_id = channel.channel_id;
                store.state.node.open_channel(channel)?;
                store.push_event(
                    EventSeverity::Info,
                    "channel_opened",
                    Some(channel_id),
                    "Channel opened in the Morph node state",
                )?;
                Ok(())
            }),
            ("POST", path) if path.starts_with("/api/channels/") => {
                self.route_channel_action(path, &request.body)
            }
            ("POST", "/api/factories") => self.mutate(|store| {
                let body: OpenFactoryRequest = parse_body(&request.body)?;
                let factory_id = parse_bytes32("factory_id", &body.factory_id)?;
                ensure!(
                    !body.participant_pubkeys.is_empty(),
                    "factory requires at least one participant"
                );
                let participant_pubkeys = body
                    .participant_pubkeys
                    .iter()
                    .map(|value| canonical_pubkey(value))
                    .collect::<Result<Vec<_>>>()?;
                let participant_node_ids = participant_pubkeys
                    .iter()
                    .map(|pubkey| node_id_from_pubkey(pubkey))
                    .collect::<Result<BTreeSet<_>>>()?;
                ensure!(
                    participant_node_ids.len() == participant_pubkeys.len(),
                    "factory participant pubkeys must be unique"
                );
                ensure!(
                    participant_node_ids.contains(&store.state.node.node_id),
                    "factory participant_pubkeys must include local pubkey"
                );
                for pubkey in &participant_pubkeys {
                    let node_id = node_id_from_pubkey(pubkey)?;
                    if node_id != store.state.node.node_id {
                        store.state.peer_pubkeys.insert(node_id, pubkey.clone());
                    }
                }
                let factory = MorphFactoryRecord {
                    factory_id,
                    participant_node_ids,
                    update_number: 0,
                    reserve_balances: vec![MorphAssetBalance {
                        asset: parse_asset(body.asset)?,
                        local: parse_amount("reserve", &body.reserve)?,
                        remote: 0,
                        pending: 0,
                    }],
                    materialised_child_channels: BTreeSet::new(),
                };
                store.state.node.open_factory(factory)?;
                store.push_event(
                    EventSeverity::Info,
                    "factory_opened",
                    Some(factory_id),
                    "Factory opened in the Morph node state",
                )?;
                Ok(())
            }),
            ("POST", path) if path.starts_with("/api/factories/") => {
                self.route_factory_action(path, &request.body)
            }
            _ => Ok(json_response(
                404,
                "Not Found",
                &json!({ "error": "unknown Morph hub endpoint" }),
            )),
        }
    }

    fn stream_events(&self, request: &HttpRequest, stream: &mut TcpStream) -> Result<()> {
        if let Some(response) = self.auth_failure_response(request) {
            write_response(stream, response, self.cors_origin.as_deref())?;
            return Ok(());
        }

        let mut last_event_id =
            parse_last_event_id(request)?.unwrap_or_else(|| self.latest_event_id());
        write_sse_headers(stream, self.cors_origin.as_deref())?;

        let mut last_heartbeat = Instant::now();
        loop {
            let events = self.events_after(last_event_id);
            for event in events {
                last_event_id = event.id;
                if write_sse_event(stream, &event).is_err() {
                    return Ok(());
                }
                last_heartbeat = Instant::now();
            }

            if last_heartbeat.elapsed() >= EVENT_STREAM_HEARTBEAT_INTERVAL {
                if write!(stream, ": keepalive\n\n").is_err() {
                    return Ok(());
                }
                if stream.flush().is_err() {
                    return Ok(());
                }
                last_heartbeat = Instant::now();
            }

            thread::sleep(EVENT_STREAM_POLL_INTERVAL);
        }
    }

    fn latest_event_id(&self) -> u64 {
        let store = self.store.lock().unwrap();
        store.state.events.first().map_or(0, |event| event.id)
    }

    fn events_after(&self, last_event_id: u64) -> Vec<HubEvent> {
        let store = self.store.lock().unwrap();
        let mut events = store
            .state
            .events
            .iter()
            .filter(|event| event.id > last_event_id)
            .cloned()
            .collect::<Vec<_>>();
        events.sort_by_key(|event| event.id);
        events
    }

    fn route_invoice_action(&self, path: &str, body: &[u8]) -> Result<HttpResponse> {
        let (invoice_id, action) = split_action_path(path, "/api/invoices/")?;
        match action {
            "receive" => self.mutate(|store| {
                store.state.node.receive_invoice(&invoice_id, now_unix()?)?;
                store.push_event(
                    EventSeverity::Info,
                    "invoice_received",
                    Some(invoice_id),
                    "Invoice marked as received",
                )?;
                Ok(())
            }),
            "settle" => self.mutate(|store| {
                let body: SettleInvoiceRequest = parse_body(body)?;
                let preimage = parse_bytes32("payment_preimage", &body.payment_preimage)?;
                store
                    .state
                    .node
                    .settle_invoice(&invoice_id, preimage, now_unix()?)?;
                store.push_event(
                    EventSeverity::Info,
                    "invoice_settled",
                    Some(invoice_id),
                    "Invoice settled with a matching preimage",
                )?;
                Ok(())
            }),
            _ => Ok(json_response(
                404,
                "Not Found",
                &json!({ "error": "unknown invoice action" }),
            )),
        }
    }

    fn route_channel_action(&self, path: &str, body: &[u8]) -> Result<HttpResponse> {
        let (channel_id, action) = split_action_path(path, "/api/channels/")?;
        match action {
            "splice" => self.mutate(|store| {
                let body: SpliceChannelRequest = parse_body(body)?;
                let new_funding_context_id =
                    parse_bytes32("new_funding_context_id", &body.new_funding_context_id)?;
                store.state.node.splice_channel(
                    &channel_id,
                    body.new_funding_epoch,
                    new_funding_context_id,
                )?;
                store.push_event(
                    EventSeverity::Warning,
                    "channel_spliced",
                    Some(channel_id),
                    "Channel funding context advanced",
                )?;
                Ok(())
            }),
            "publish" => self.mutate(|store| {
                let body: PublishStateRequest = parse_body(body)?;
                let funding_context_id =
                    parse_bytes32("funding_context_id", &body.funding_context_id)?;
                store.state.node.publish_state(
                    &channel_id,
                    funding_context_id,
                    body.state_number,
                )?;
                store.push_event(
                    EventSeverity::Warning,
                    "state_published",
                    Some(channel_id),
                    "Latest channel state published",
                )?;
                Ok(())
            }),
            "finalise" => self.mutate(|store| {
                ensure!(body.is_empty(), "finalise request body must be empty");
                store.state.node.finalise_channel(&channel_id)?;
                store.push_event(
                    EventSeverity::Info,
                    "channel_finalised",
                    Some(channel_id),
                    "Settling channel finalised",
                )?;
                Ok(())
            }),
            _ => Ok(json_response(
                404,
                "Not Found",
                &json!({ "error": "unknown channel action" }),
            )),
        }
    }

    fn route_factory_action(&self, path: &str, body: &[u8]) -> Result<HttpResponse> {
        let (factory_id, action) = split_action_path(path, "/api/factories/")?;
        match action {
            "advance" => self.mutate(|store| {
                let body: AdvanceFactoryRequest = parse_body(body)?;
                store
                    .state
                    .node
                    .advance_factory(&factory_id, body.new_update_number)?;
                store.push_event(
                    EventSeverity::Info,
                    "factory_advanced",
                    Some(factory_id),
                    "Factory update number advanced",
                )?;
                Ok(())
            }),
            "materialise-child" => self.mutate(|store| {
                let body: MaterialiseChildRequest = parse_body(body)?;
                let counterparty_pubkey = canonical_pubkey(&body.counterparty_pubkey)?;
                let counterparty_node_id = node_id_from_pubkey(&counterparty_pubkey)?;
                ensure_peer(
                    &mut store.state,
                    &counterparty_pubkey,
                    counterparty_node_id,
                    body.counterparty_alias.as_deref(),
                )?;
                let child = channel_from_request(
                    &body.child_channel_id,
                    counterparty_node_id,
                    &body.funding_context_id,
                    &body.local,
                    &body.remote,
                    body.pending.as_deref(),
                    body.sponsor_budget,
                    body.asset,
                )?;
                let child_channel_id = child.channel_id;
                store
                    .state
                    .node
                    .materialise_child_channel(&factory_id, child)?;
                store.push_event(
                    EventSeverity::Info,
                    "factory_child_materialised",
                    Some(child_channel_id),
                    "Factory child channel materialised",
                )?;
                Ok(())
            }),
            _ => Ok(json_response(
                404,
                "Not Found",
                &json!({ "error": "unknown factory action" }),
            )),
        }
    }

    fn mutate<F>(&self, f: F) -> Result<HttpResponse>
    where
        F: FnOnce(&mut HubStore) -> Result<()>,
    {
        let mut store = self.store.lock().unwrap();
        let mut candidate = store.clone();
        f(&mut candidate)?;
        let view = candidate.view(self.rpc_view(), self.security_view())?;
        candidate.persist()?;
        *store = candidate;
        Ok(json_response(200, "OK", &view))
    }

    fn state_response(&self) -> Result<HttpResponse> {
        let store = self.store.lock().unwrap();
        let view = store.view(self.rpc_view(), self.security_view())?;
        Ok(json_response(200, "OK", &view))
    }

    fn auth_failure_response(&self, request: &HttpRequest) -> Option<HttpResponse> {
        let token = self.auth_token.as_ref()?;
        let bearer = format!("Bearer {token}");
        let authorised = request
            .header("authorization")
            .is_some_and(|value| value == bearer)
            || request
                .header("x-morph-hub-token")
                .is_some_and(|value| value == token);
        (!authorised).then(|| {
            json_response(
                401,
                "Unauthorized",
                &json!({ "error": "missing or invalid Morph Hub auth token" }),
            )
        })
    }

    fn security_view(&self) -> HubSecurityView {
        HubSecurityView {
            auth_required: self.auth_token.is_some(),
            state_restore_enabled: self.allow_state_restore,
            cors_origin: self.cors_origin.clone(),
        }
    }

    fn rpc_view(&self) -> RpcView {
        let Some(url) = self.ckb_rpc_url.clone() else {
            return RpcView {
                status: "not_configured",
                url: None,
                tip_height: None,
                chain: None,
                message: Some("start with --ckb-rpc-url to enable live chain health".to_string()),
            };
        };
        match CkbRpcClient::new(url.clone()).and_then(|client| client.status()) {
            Ok(status) => RpcView {
                status: if status.node.active {
                    "connected"
                } else {
                    "degraded"
                },
                url: Some(url),
                tip_height: status.tip.number_value().ok(),
                chain: Some(status.chain.chain),
                message: None,
            },
            Err(err) => RpcView {
                status: "offline",
                url: Some(url),
                tip_height: None,
                chain: None,
                message: Some(err.to_string()),
            },
        }
    }

    fn route_static(&self, request: HttpRequest) -> Result<HttpResponse> {
        ensure!(request.method == "GET", "static assets only support GET");
        let path = static_path(&self.ui_dir, &request.path)?;
        if path.exists() && path.is_file() {
            let body = fs::read(&path)
                .with_context(|| format!("failed to read static asset {}", path.display()))?;
            return Ok(HttpResponse {
                status: 200,
                reason: "OK",
                content_type: content_type(&path),
                body,
            });
        }
        let index = self.ui_dir.join("index.html");
        if index.exists() {
            return Ok(HttpResponse {
                status: 200,
                reason: "OK",
                content_type: "text/html; charset=utf-8",
                body: fs::read(index)?,
            });
        }
        Ok(json_response(
            404,
            "Not Found",
            &json!({
                "error": format!(
                    "hub UI not built at {}; run npm run build in ui/morph-hub",
                    self.ui_dir.display()
                )
            }),
        ))
    }
}

fn ensure_peer(
    state: &mut HubRuntimeState,
    pubkey: &str,
    counterparty_node_id: Bytes32,
    alias: Option<&str>,
) -> Result<()> {
    ensure!(
        counterparty_node_id != state.node.node_id,
        "counterparty pubkey must not be local pubkey"
    );
    if state.node.peers.contains_key(&counterparty_node_id) {
        state
            .peer_pubkeys
            .entry(counterparty_node_id)
            .or_insert_with(|| pubkey.to_string());
        return Ok(());
    }
    state.node.connect_peer(MorphPeer {
        node_id: counterparty_node_id,
        alias: alias
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| pubkey.to_string()),
    })?;
    state
        .peer_pubkeys
        .insert(counterparty_node_id, pubkey.to_string());
    Ok(())
}

fn channel_from_request(
    channel_id: &str,
    counterparty_node_id: Bytes32,
    funding_context_id: &str,
    local: &str,
    remote: &str,
    pending: Option<&str>,
    sponsor_budget: u64,
    asset: Option<AssetRequest>,
) -> Result<MorphChannelRecord> {
    Ok(MorphChannelRecord {
        channel_id: parse_bytes32("channel_id", channel_id)?,
        counterparty_node_id,
        funding_epoch: 0,
        funding_context_id: parse_bytes32("funding_context_id", funding_context_id)?,
        state_number: 1,
        phase: Phase::Active,
        balances: vec![MorphAssetBalance {
            asset: parse_asset(asset)?,
            local: parse_amount("local", local)?,
            remote: parse_amount("remote", remote)?,
            pending: parse_amount("pending", pending.unwrap_or("0"))?,
        }],
        sponsor_budget,
    })
}

fn split_action_path<'a>(path: &'a str, prefix: &str) -> Result<(Bytes32, &'a str)> {
    let suffix = path
        .strip_prefix(prefix)
        .ok_or_else(|| anyhow!("invalid action path"))?;
    let (id, action) = suffix
        .split_once('/')
        .ok_or_else(|| anyhow!("action path must include an id and action"))?;
    Ok((parse_bytes32("id", id)?, action))
}

fn write_private_file_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("hub state path must include a file name"))?;
    let tmp_path = path.with_file_name(format!(".{file_name}.{}.tmp", std::process::id()));
    let _ = fs::remove_file(&tmp_path);
    let mut file = create_private_new_file(&tmp_path)?;
    file.write_all(data)
        .with_context(|| format!("failed to write {}", tmp_path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync {}", tmp_path.display()))?;
    drop(file);
    fs::rename(&tmp_path, path)
        .with_context(|| format!("failed to atomically replace hub state {}", path.display()))?;
    sync_parent_dir(path)?;
    Ok(())
}

fn create_private_new_file(path: &Path) -> Result<fs::File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    options
        .open(path)
        .with_context(|| format!("failed to create private file {}", path.display()))
}

#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::File::open(parent)
            .and_then(|dir| dir.sync_all())
            .with_context(|| format!("failed to sync directory {}", parent.display()))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) -> Result<()> {
    Ok(())
}

fn parse_body<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T> {
    ensure!(!body.is_empty(), "request body must not be empty");
    serde_json::from_slice(body).context("request body is not valid JSON")
}

fn parse_asset(asset: Option<AssetRequest>) -> Result<MorphAsset> {
    match asset.unwrap_or(AssetRequest::Ckb) {
        AssetRequest::Ckb => Ok(MorphAsset::Ckb),
        AssetRequest::Xudt { type_hash } => Ok(MorphAsset::Xudt(parse_bytes32(
            "asset.type_hash",
            &type_hash,
        )?)),
    }
}

fn parse_amount(label: &str, value: &str) -> Result<u128> {
    let value = value.trim();
    ensure!(!value.is_empty(), "{label} must not be empty");
    let amount = value
        .parse::<u128>()
        .with_context(|| format!("{label} must be an unsigned integer"))?;
    ensure!(
        amount > 0 || label == "pending",
        "{label} must be greater than zero"
    );
    Ok(amount)
}

fn canonical_pubkey(value: &str) -> Result<String> {
    Ok(hex::encode(parse_pubkey_bytes(value)?))
}

fn node_id_from_pubkey(pubkey: &str) -> Result<Bytes32> {
    let bytes = parse_pubkey_bytes(pubkey)?;
    Ok(blake2b256(&bytes))
}

fn parse_pubkey_bytes(value: &str) -> Result<[u8; 33]> {
    let value = value.trim().to_lowercase();
    ensure!(
        !value.is_empty(),
        "pubkey must not be empty; pass a 33-byte compressed secp256k1 pubkey as 66 hex characters without 0x"
    );
    ensure!(
        !value.starts_with("0x"),
        "pubkey must be hex without 0x, matching Fiber RPC convention"
    );
    ensure!(
        value.len() == 66,
        "pubkey must be a 33-byte compressed secp256k1 pubkey encoded as 66 hex characters"
    );
    let raw = hex::decode(&value).context("pubkey is not valid hex")?;
    let mut out = [0u8; 33];
    out.copy_from_slice(&raw);
    ensure!(
        matches!(out[0], 0x02 | 0x03),
        "pubkey must be a compressed secp256k1 public key starting with 02 or 03"
    );
    k256::PublicKey::from_sec1_bytes(&out)
        .map_err(|_| anyhow!("pubkey is not a valid secp256k1 public key"))?;
    Ok(out)
}

fn parse_bytes32(label: &str, value: &str) -> Result<Bytes32> {
    let value = value.trim();
    let hex = value
        .strip_prefix("0x")
        .ok_or_else(|| anyhow!("{label} must be 0x-prefixed"))?;
    ensure!(hex.len() == 64, "{label} must be 32 bytes");
    let raw = hex::decode(hex).with_context(|| format!("{label} is not valid hex"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    ensure!(
        out.iter().any(|byte| *byte != 0),
        "{label} must not be zero"
    );
    Ok(out)
}

fn read_request(stream: &mut TcpStream) -> Result<HttpRequest> {
    read_request_from_reader(stream)
}

fn read_request_from_reader(reader: impl Read) -> Result<HttpRequest> {
    let mut reader = BufReader::new(reader);
    let (request_line, mut header_bytes) = read_limited_line(&mut reader, MAX_REQUEST_LINE_BYTES)?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| anyhow!("missing HTTP method"))?
        .to_string();
    let uri = parts
        .next()
        .ok_or_else(|| anyhow!("missing HTTP path"))?
        .to_string();
    let version = parts
        .next()
        .ok_or_else(|| anyhow!("missing HTTP version"))?;
    ensure!(parts.next().is_none(), "malformed HTTP request line");
    ensure!(
        version.starts_with("HTTP/"),
        "unsupported HTTP request version"
    );
    let path = uri.split('?').next().unwrap_or(&uri).to_string();

    let mut content_length = 0usize;
    let mut headers = BTreeMap::new();
    loop {
        let (line, line_bytes) = read_limited_line(&mut reader, MAX_REQUEST_LINE_BYTES)?;
        header_bytes = header_bytes
            .checked_add(line_bytes)
            .context("HTTP headers are too large")?;
        ensure!(
            header_bytes <= MAX_REQUEST_HEADER_BYTES,
            "HTTP headers exceed {} bytes",
            MAX_REQUEST_HEADER_BYTES
        );
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value
                    .trim()
                    .parse::<usize>()
                    .context("invalid Content-Length")?;
                ensure!(
                    content_length <= MAX_REQUEST_BODY_BYTES,
                    "request body exceeds {} bytes",
                    MAX_REQUEST_BODY_BYTES
                );
            }
        }
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }

    Ok(HttpRequest {
        method,
        path,
        headers,
        body,
    })
}

fn read_limited_line(reader: &mut impl BufRead, max_bytes: usize) -> Result<(String, usize)> {
    let mut buf = Vec::new();
    loop {
        let available = reader.fill_buf().context("failed to read HTTP line")?;
        ensure!(
            !available.is_empty(),
            "unexpected EOF while reading HTTP line"
        );
        if let Some(newline_index) = available.iter().position(|byte| *byte == b'\n') {
            let take = newline_index + 1;
            ensure!(
                buf.len() + take <= max_bytes,
                "HTTP line exceeds {} bytes",
                max_bytes
            );
            buf.extend_from_slice(&available[..take]);
            reader.consume(take);
            break;
        }
        ensure!(
            buf.len() + available.len() <= max_bytes,
            "HTTP line exceeds {} bytes",
            max_bytes
        );
        let take = available.len();
        buf.extend_from_slice(available);
        reader.consume(take);
    }
    let bytes = buf.len();
    let line = String::from_utf8(buf)
        .context("HTTP line is not valid UTF-8")?
        .trim_end_matches(['\r', '\n'])
        .to_string();
    Ok((line, bytes))
}

fn write_response(
    stream: &mut TcpStream,
    response: HttpResponse,
    cors_origin: Option<&str>,
) -> Result<()> {
    write!(
        stream,
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n",
        response.status,
        response.reason,
        response.content_type,
        response.body.len()
    )?;
    if let Some(origin) = cors_origin {
        write!(
            stream,
            "Access-Control-Allow-Origin: {origin}\r\nVary: Origin\r\nAccess-Control-Allow-Methods: GET, POST, PUT, OPTIONS\r\nAccess-Control-Allow-Headers: content-type, authorization, x-morph-hub-token\r\n"
        )?;
    }
    write!(stream, "Connection: close\r\n\r\n")?;
    stream.write_all(&response.body)?;
    stream.flush()?;
    Ok(())
}

fn write_sse_headers(stream: &mut TcpStream, cors_origin: Option<&str>) -> Result<()> {
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n"
    )?;
    if let Some(origin) = cors_origin {
        write!(
            stream,
            "Access-Control-Allow-Origin: {origin}\r\nVary: Origin\r\nAccess-Control-Allow-Headers: content-type, authorization, x-morph-hub-token\r\n"
        )?;
    }
    write!(stream, "\r\n")?;
    stream.flush()?;
    Ok(())
}

fn write_sse_event(stream: &mut TcpStream, event: &HubEvent) -> Result<()> {
    let data = serde_json::to_string(&event_view(event))
        .context("failed to serialise Morph Hub SSE event")?;
    write!(stream, "id: {}\nevent: morph-hub-event\n", event.id)?;
    for line in data.lines() {
        writeln!(stream, "data: {line}")?;
    }
    writeln!(stream)?;
    stream.flush()?;
    Ok(())
}

fn parse_last_event_id(request: &HttpRequest) -> Result<Option<u64>> {
    let Some(value) = request.header("last-event-id") else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    value
        .parse::<u64>()
        .map(Some)
        .context("Last-Event-ID must be an unsigned integer")
}

fn json_response<T: Serialize>(status: u16, reason: &'static str, value: &T) -> HttpResponse {
    HttpResponse {
        status,
        reason,
        content_type: "application/json; charset=utf-8",
        body: serde_json::to_vec_pretty(value)
            .unwrap_or_else(|_| b"{\"error\":\"failed to serialise response\"}".to_vec()),
    }
}

fn empty_response(status: u16, reason: &'static str) -> HttpResponse {
    HttpResponse {
        status,
        reason,
        content_type: "text/plain; charset=utf-8",
        body: Vec::new(),
    }
}

fn static_path(ui_dir: &Path, request_path: &str) -> Result<PathBuf> {
    let clean = request_path.trim_start_matches('/');
    ensure!(
        !clean.split('/').any(|part| part == ".."),
        "static path must not traverse directories"
    );
    Ok(if clean.is_empty() {
        ui_dir.join("index.html")
    } else {
        ui_dir.join(clean)
    })
}

fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("json") => "application/json; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn persisted_peer(
    peer: &MorphPeer,
    peer_pubkeys: &BTreeMap<Bytes32, String>,
) -> Result<PersistedPeer> {
    Ok(PersistedPeer {
        pubkey: pubkey_for_node_id(&peer.node_id, peer_pubkeys)?.to_string(),
        alias: peer.alias.clone(),
    })
}

fn persisted_channel(
    channel: &MorphChannelRecord,
    peer_pubkeys: &BTreeMap<Bytes32, String>,
) -> Result<PersistedChannel> {
    Ok(PersistedChannel {
        channel_id: hex_prefixed(&channel.channel_id),
        counterparty_pubkey: pubkey_for_node_id(&channel.counterparty_node_id, peer_pubkeys)?
            .to_string(),
        funding_epoch: channel.funding_epoch,
        funding_context_id: hex_prefixed(&channel.funding_context_id),
        state_number: channel.state_number,
        phase: channel.phase,
        balances: channel.balances.clone(),
        sponsor_budget: channel.sponsor_budget,
    })
}

fn persisted_factory(
    factory: &MorphFactoryRecord,
    local_node_id: Bytes32,
    local_pubkey: &str,
    peer_pubkeys: &BTreeMap<Bytes32, String>,
) -> Result<PersistedFactory> {
    Ok(PersistedFactory {
        factory_id: hex_prefixed(&factory.factory_id),
        participant_pubkeys: participant_pubkeys(
            &factory.participant_node_ids,
            local_node_id,
            local_pubkey,
            peer_pubkeys,
        )?,
        update_number: factory.update_number,
        reserve_balances: factory.reserve_balances.clone(),
        materialised_child_channels: factory
            .materialised_child_channels
            .iter()
            .map(|id| hex_prefixed(id))
            .collect(),
    })
}

fn peer_view(peer: &MorphPeer, peer_pubkeys: &BTreeMap<Bytes32, String>) -> Result<PeerView> {
    Ok(PeerView {
        pubkey: pubkey_for_node_id(&peer.node_id, peer_pubkeys)?.to_string(),
        node_id: hex_prefixed(&peer.node_id),
        alias: peer.alias.clone(),
        provenance: local_state_provenance(),
    })
}

fn channel_view(
    channel: &MorphChannelRecord,
    peer_pubkeys: &BTreeMap<Bytes32, String>,
) -> Result<ChannelView> {
    Ok(ChannelView {
        channel_id: hex_prefixed(&channel.channel_id),
        counterparty_pubkey: pubkey_for_node_id(&channel.counterparty_node_id, peer_pubkeys)?
            .to_string(),
        counterparty_node_id: hex_prefixed(&channel.counterparty_node_id),
        funding_epoch: channel.funding_epoch,
        funding_context_id: hex_prefixed(&channel.funding_context_id),
        state_number: channel.state_number,
        phase: phase_label(channel.phase),
        balances: channel.balances.iter().map(balance_view).collect(),
        sponsor_budget: channel.sponsor_budget,
        provenance: local_state_provenance(),
    })
}

fn invoice_view(
    stored: &StoredMorphInvoice,
    local_node_id: Bytes32,
    local_pubkey: &str,
) -> InvoiceView {
    InvoiceView {
        invoice_id: hex_prefixed(&stored.invoice.invoice_id),
        encoded_invoice: stored.encoded_invoice.clone(),
        status: invoice_status_label(stored.status),
        network: network_label(stored.invoice.network),
        payee_pubkey: (stored.invoice.payee_node_id == local_node_id)
            .then(|| local_pubkey.to_string()),
        payee_node_id: hex_prefixed(&stored.invoice.payee_node_id),
        channel_id: stored.invoice.channel_id.map(|id| hex_prefixed(&id)),
        asset: asset_view(&stored.invoice.asset),
        amount: stored.invoice.amount.to_string(),
        created_at_unix: stored.invoice.created_at_unix,
        expires_at_unix: stored.invoice.expires_at_unix,
        payment_hash: hex_prefixed(&stored.invoice.payment_hash),
        description: stored.invoice.description.clone(),
        received_at_unix: stored.received_at_unix,
        paid_at_unix: stored.paid_at_unix,
        cancelled_at_unix: stored.cancelled_at_unix,
        provenance: local_state_provenance(),
    }
}

fn factory_view(
    factory: &MorphFactoryRecord,
    local_node_id: Bytes32,
    local_pubkey: &str,
    peer_pubkeys: &BTreeMap<Bytes32, String>,
) -> Result<FactoryView> {
    Ok(FactoryView {
        factory_id: hex_prefixed(&factory.factory_id),
        participant_pubkeys: participant_pubkeys(
            &factory.participant_node_ids,
            local_node_id,
            local_pubkey,
            peer_pubkeys,
        )?,
        participant_node_ids: factory
            .participant_node_ids
            .iter()
            .map(|id| hex_prefixed(id))
            .collect(),
        update_number: factory.update_number,
        reserve_balances: factory.reserve_balances.iter().map(balance_view).collect(),
        materialised_child_channels: factory
            .materialised_child_channels
            .iter()
            .map(|id| hex_prefixed(id))
            .collect(),
        provenance: local_state_provenance(),
    })
}

fn participant_pubkeys(
    participant_node_ids: &BTreeSet<Bytes32>,
    local_node_id: Bytes32,
    local_pubkey: &str,
    peer_pubkeys: &BTreeMap<Bytes32, String>,
) -> Result<Vec<String>> {
    participant_node_ids
        .iter()
        .map(|id| {
            if *id == local_node_id {
                Ok(local_pubkey.to_string())
            } else {
                Ok(pubkey_for_node_id(id, peer_pubkeys)?.to_string())
            }
        })
        .collect()
}

fn pubkey_for_node_id<'a>(
    node_id: &Bytes32,
    peer_pubkeys: &'a BTreeMap<Bytes32, String>,
) -> Result<&'a str> {
    peer_pubkeys
        .get(node_id)
        .map(String::as_str)
        .ok_or_else(|| anyhow!("missing pubkey for node id {}", hex_prefixed(node_id)))
}

fn balance_view(balance: &MorphAssetBalance) -> BalanceView {
    BalanceView {
        asset: asset_view(&balance.asset),
        local: balance.local.to_string(),
        remote: balance.remote.to_string(),
        pending: balance.pending.to_string(),
    }
}

fn event_view(event: &HubEvent) -> EventView {
    EventView {
        id: event.id,
        severity: event.severity,
        event: event.event.clone(),
        subject_id: event.subject_id.map(|id| hex_prefixed(&id)),
        message: event.message.clone(),
        created_at_unix: event.created_at_unix,
        provenance: local_state_provenance(),
    }
}

fn asset_view(asset: &MorphAsset) -> AssetView {
    match asset {
        MorphAsset::Ckb => AssetView::Ckb,
        MorphAsset::Xudt(type_hash) => AssetView::Xudt {
            type_hash: hex_prefixed(type_hash),
        },
    }
}

fn network_label(network: MorphNetwork) -> &'static str {
    match network {
        MorphNetwork::Devnet => "devnet",
        MorphNetwork::Testnet => "testnet",
        MorphNetwork::Mainnet => "mainnet",
    }
}

fn phase_label(phase: Phase) -> &'static str {
    match phase {
        Phase::Funding => "funding",
        Phase::Active => "active",
        Phase::Settling => "settling",
        Phase::Closed => "closed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    static TEST_STATE_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn request_parser_rejects_oversized_request_lines() {
        let valid = b"GET /api/state HTTP/1.1\r\nHost: morph.local\r\n\r\n";
        let request = read_request_from_reader(Cursor::new(valid)).unwrap();
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/api/state");

        let oversized = format!(
            "GET /{} HTTP/1.1\r\nHost: morph.local\r\n\r\n",
            "a".repeat(MAX_REQUEST_LINE_BYTES)
        );
        let err = read_request_from_reader(Cursor::new(oversized.into_bytes()))
            .expect_err("oversized HTTP request line should be rejected");
        assert!(
            err.to_string().contains("HTTP line exceeds"),
            "unexpected error: {err:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn hub_state_file_is_owner_only_after_sensitive_invoice_persist() {
        let local_pubkey = pubkey_from_scalar(1);
        let server = test_server(&local_pubkey);
        let path = server.store.lock().unwrap().path.clone();
        assert_eq!(state_file_mode(&path), 0o600);

        let response = route_json(
            &server,
            "POST",
            "/api/invoices",
            json!({
                "amount": "100000000",
                "description": "private invoice",
                "payment_preimage": bytes32_hex(51),
                "expiry_secs": 3600,
                "asset": { "kind": "ckb" }
            }),
        );
        assert_eq!(response.status, 200);
        assert_eq!(state_file_mode(&path), 0o600);

        let persisted = fs::read_to_string(&path).unwrap();
        assert!(persisted.contains("payment_preimage"));
    }

    #[test]
    fn rejected_mutation_does_not_commit_partial_peer_state() {
        let local_pubkey = pubkey_from_scalar(1);
        let peer_one_pubkey = pubkey_from_scalar(2);
        let peer_two_pubkey = pubkey_from_scalar(3);
        let server = test_server(&local_pubkey);

        let factory_id = hex_repeat('5');
        let child_id = hex_repeat('6');
        let funding_context_id = hex_repeat('7');
        let response = route_json(
            &server,
            "POST",
            "/api/factories",
            json!({
                "factory_id": factory_id,
                "participant_pubkeys": [local_pubkey.as_str(), peer_one_pubkey.as_str()],
                "reserve": "500000000",
                "asset": { "kind": "ckb" }
            }),
        );
        assert_eq!(response.status, 200);

        let response = route_json(
            &server,
            "POST",
            &format!("/api/factories/{factory_id}/materialise-child"),
            json!({
                "child_channel_id": child_id,
                "counterparty_pubkey": peer_two_pubkey.as_str(),
                "counterparty_alias": "not-member",
                "funding_context_id": funding_context_id,
                "local": "100000000",
                "remote": "100000000",
                "sponsor_budget": 1000000,
                "asset": { "kind": "ckb" }
            }),
        );
        assert_eq!(response.status, 400);

        let state = route_empty(&server, "GET", "/api/state");
        assert_eq!(state.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&state.body).unwrap();
        let peers = body["peers"].as_array().unwrap();
        assert!(
            peers
                .iter()
                .all(|peer| peer["pubkey"].as_str() != Some(peer_two_pubkey.as_str())),
            "failed materialise-child request leaked non-participant peer into hub state"
        );

        let response = route_json(
            &server,
            "POST",
            &format!("/api/factories/{factory_id}/materialise-child"),
            json!({
                "child_channel_id": child_id,
                "counterparty_pubkey": peer_one_pubkey.as_str(),
                "counterparty_alias": "member",
                "funding_context_id": funding_context_id,
                "local": "100000000",
                "remote": "100000000",
                "sponsor_budget": 1000000,
                "asset": { "kind": "ckb" }
            }),
        );
        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(
            body["peers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|peer| peer["pubkey"].as_str() == Some(peer_one_pubkey.as_str()))
        );
        assert!(
            body["channels"]
                .as_array()
                .unwrap()
                .iter()
                .any(|channel| channel["channel_id"].as_str() == Some(child_id.as_str()))
        );
        assert!(
            body["completed_flows"]
                .as_array()
                .unwrap()
                .iter()
                .any(|flow| flow.as_str() == Some("factory-child"))
        );
    }

    #[test]
    fn state_restore_is_disabled_by_default() {
        let local_pubkey = pubkey_from_scalar(1);
        let server = test_server(&local_pubkey);
        let state = route_empty(&server, "GET", "/api/state");
        let persisted: serde_json::Value = serde_json::from_slice(&state.body).unwrap();

        let response = route_json(&server, "PUT", "/api/state-file", persisted);

        assert_eq!(response.status, 403);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("--allow-state-restore")
        );
    }

    #[test]
    fn existing_state_file_must_match_requested_network() {
        let local_pubkey = pubkey_from_scalar(1);
        let server = test_server(&local_pubkey);
        let path = server.store.lock().unwrap().path.clone();

        let err = match HubStore::load_or_create(path, &local_pubkey, MorphNetwork::Testnet) {
            Ok(_) => panic!("network-mismatched hub state file was accepted"),
            Err(err) => err,
        };

        assert!(
            err.to_string().contains("hub state network devnet"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn state_restore_rejects_pubkey_mismatch_without_commit() {
        let local_pubkey = pubkey_from_scalar(1);
        let other_pubkey = pubkey_from_scalar(2);
        let server = test_server_with_options(&local_pubkey, None, true, None);
        let response = route_empty(&server, "GET", "/api/state-file");
        assert_eq!(response.status, 200);
        let mut persisted: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        persisted["pubkey"] = json!(other_pubkey);

        let response = route_json(&server, "PUT", "/api/state-file", persisted);

        assert_eq!(response.status, 400);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("does not match running pubkey")
        );
        let state = route_empty(&server, "GET", "/api/state");
        let body: serde_json::Value = serde_json::from_slice(&state.body).unwrap();
        assert_eq!(body["pubkey"].as_str(), Some(local_pubkey.as_str()));
        assert_eq!(body["events"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn state_restore_rejects_network_mismatch_without_commit() {
        let local_pubkey = pubkey_from_scalar(1);
        let server = test_server_with_options(&local_pubkey, None, true, None);
        let response = route_empty(&server, "GET", "/api/state-file");
        assert_eq!(response.status, 200);
        let mut persisted: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        persisted["network"] = serde_json::to_value(MorphNetwork::Testnet).unwrap();

        let response = route_json(&server, "PUT", "/api/state-file", persisted);

        assert_eq!(response.status, 400);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("does not match running network")
        );
        let state = route_empty(&server, "GET", "/api/state");
        let body: serde_json::Value = serde_json::from_slice(&state.body).unwrap();
        assert_eq!(body["network"].as_str(), Some("devnet"));
        assert_eq!(body["events"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn auth_token_protects_api_routes() {
        let local_pubkey = pubkey_from_scalar(1);
        let server = test_server_with_options(&local_pubkey, Some("secret-token"), false, None);

        let response = route_empty(&server, "GET", "/api/state");
        assert_eq!(response.status, 401);

        let response = route_empty_with_headers(
            &server,
            "GET",
            "/api/state",
            [("authorization", "Bearer secret-token")],
        );
        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["security"]["auth_required"].as_bool(), Some(true));
    }

    #[test]
    fn event_stream_uses_api_auth_and_cursor_ordering() {
        let local_pubkey = pubkey_from_scalar(1);
        let peer_pubkey = pubkey_from_scalar(2);
        let server = test_server_with_options(&local_pubkey, Some("secret-token"), false, None);
        let unauthorised = request_empty("GET", "/api/events", std::iter::empty::<(&str, &str)>());
        assert!(server.auth_failure_response(&unauthorised).is_some());

        let authorised = request_empty(
            "GET",
            "/api/events",
            [("authorization", "Bearer secret-token")],
        );
        assert!(server.auth_failure_response(&authorised).is_none());
        assert_eq!(parse_last_event_id(&authorised).unwrap(), None);

        let response = route_json_with_headers(
            &server,
            "POST",
            "/api/peers",
            json!({
                "pubkey": peer_pubkey,
                "alias": "stream-peer"
            }),
            [("authorization", "Bearer secret-token")],
        );
        assert_eq!(response.status, 200);
        let response = route_json_with_headers(
            &server,
            "POST",
            "/api/invoices",
            json!({
                "amount": "100000000",
                "description": "stream invoice",
                "payment_preimage": bytes32_hex(41),
                "expiry_secs": 3600,
                "asset": { "kind": "ckb" }
            }),
            [("authorization", "Bearer secret-token")],
        );
        assert_eq!(response.status, 200);

        let events = server.events_after(0);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].id, 1);
        assert_eq!(events[0].event, "peer_connected");
        assert_eq!(events[1].id, 2);
        assert_eq!(events[1].event, "invoice_created");
        assert_eq!(server.events_after(1).len(), 1);

        let resumed = request_empty("GET", "/api/events", [("last-event-id", "1")]);
        assert_eq!(parse_last_event_id(&resumed).unwrap(), Some(1));
    }

    #[test]
    fn invoice_api_flow_creates_receives_and_settles() {
        let local_pubkey = pubkey_from_scalar(1);
        let server = test_server(&local_pubkey);
        let preimage = bytes32_hex(11);

        let response = route_json(
            &server,
            "POST",
            "/api/invoices",
            json!({
                "amount": "100000000",
                "description": "integration invoice",
                "payment_preimage": preimage,
                "expiry_secs": 3600,
                "asset": { "kind": "ckb" }
            }),
        );
        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        let invoice_id = body["invoices"][0]["invoice_id"].as_str().unwrap();
        assert_eq!(
            body["invoices"][0]["provenance"]["chain_status"].as_str(),
            Some("not_chain_verified")
        );

        let response = route_empty(
            &server,
            "POST",
            format!("/api/invoices/{invoice_id}/receive"),
        );
        assert_eq!(response.status, 200);

        let response = route_json(
            &server,
            "POST",
            format!("/api/invoices/{invoice_id}/settle"),
            json!({ "payment_preimage": preimage }),
        );
        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["invoices"][0]["status"].as_str(), Some("paid"));
        assert!(
            body["completed_flows"]
                .as_array()
                .unwrap()
                .iter()
                .any(|flow| flow.as_str() == Some("invoice-settled"))
        );
    }

    #[test]
    fn channel_api_flow_opens_splices_publishes_and_finalises() {
        let local_pubkey = pubkey_from_scalar(1);
        let peer_pubkey = pubkey_from_scalar(2);
        let server = test_server(&local_pubkey);
        let channel_id = bytes32_hex(21);

        let response = route_json(
            &server,
            "POST",
            "/api/channels",
            json!({
                "channel_id": channel_id,
                "counterparty_pubkey": peer_pubkey,
                "counterparty_alias": "counterparty",
                "funding_context_id": bytes32_hex(22),
                "local": "100000000",
                "remote": "200000000",
                "sponsor_budget": 1000000,
                "asset": { "kind": "ckb" }
            }),
        );
        assert_eq!(response.status, 200);

        let response = route_json(
            &server,
            "POST",
            format!("/api/channels/{channel_id}/splice"),
            json!({
                "new_funding_epoch": 2,
                "new_funding_context_id": bytes32_hex(23)
            }),
        );
        assert_eq!(response.status, 200);

        let response = route_json(
            &server,
            "POST",
            format!("/api/channels/{channel_id}/publish"),
            json!({
                "funding_context_id": bytes32_hex(23),
                "state_number": 3
            }),
        );
        assert_eq!(response.status, 200);

        let response = route_empty(
            &server,
            "POST",
            format!("/api/channels/{channel_id}/finalise"),
        );
        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["channels"][0]["phase"].as_str(), Some("closed"));
        assert!(
            body["completed_flows"]
                .as_array()
                .unwrap()
                .iter()
                .any(|flow| flow.as_str() == Some("channel-finalised"))
        );
    }

    #[test]
    fn factory_api_flow_opens_advances_and_materialises_child() {
        let local_pubkey = pubkey_from_scalar(1);
        let peer_pubkey = pubkey_from_scalar(2);
        let server = test_server(&local_pubkey);
        let factory_id = bytes32_hex(31);
        let child_id = bytes32_hex(32);

        let response = route_json(
            &server,
            "POST",
            "/api/factories",
            json!({
                "factory_id": factory_id,
                "participant_pubkeys": [local_pubkey.as_str(), peer_pubkey.as_str()],
                "reserve": "500000000",
                "asset": { "kind": "ckb" }
            }),
        );
        assert_eq!(response.status, 200);

        let response = route_json(
            &server,
            "POST",
            format!("/api/factories/{factory_id}/advance"),
            json!({ "new_update_number": 2 }),
        );
        assert_eq!(response.status, 200);

        let response = route_json(
            &server,
            "POST",
            format!("/api/factories/{factory_id}/materialise-child"),
            json!({
                "child_channel_id": child_id,
                "counterparty_pubkey": peer_pubkey,
                "counterparty_alias": "member",
                "funding_context_id": bytes32_hex(33),
                "local": "100000000",
                "remote": "100000000",
                "sponsor_budget": 1000000,
                "asset": { "kind": "ckb" }
            }),
        );
        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["factories"][0]["update_number"].as_u64(), Some(2));
        assert_eq!(
            body["factories"][0]["materialised_child_channels"][0].as_str(),
            Some(child_id.as_str())
        );
        assert!(
            body["completed_flows"]
                .as_array()
                .unwrap()
                .iter()
                .any(|flow| flow.as_str() == Some("factory-child"))
        );
    }

    #[test]
    fn hub_api_can_complete_all_required_business_flows() {
        let local_pubkey = pubkey_from_scalar(1);
        let peer_pubkey = pubkey_from_scalar(2);
        let channel_peer_pubkey = pubkey_from_scalar(3);
        let server = test_server(&local_pubkey);

        let response = route_json(
            &server,
            "POST",
            "/api/peers",
            json!({
                "pubkey": peer_pubkey,
                "alias": "all-flow-peer"
            }),
        );
        assert_eq!(response.status, 200);

        let preimage = bytes32_hex(41);
        let response = route_json(
            &server,
            "POST",
            "/api/invoices",
            json!({
                "amount": "100000000",
                "description": "all-flow invoice",
                "payment_preimage": preimage,
                "expiry_secs": 3600,
                "asset": { "kind": "ckb" }
            }),
        );
        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        let invoice_id = body["invoices"]
            .as_array()
            .unwrap()
            .iter()
            .find(|invoice| invoice["description"].as_str() == Some("all-flow invoice"))
            .and_then(|invoice| invoice["invoice_id"].as_str())
            .unwrap()
            .to_string();

        let response = route_empty(
            &server,
            "POST",
            format!("/api/invoices/{invoice_id}/receive"),
        );
        assert_eq!(response.status, 200);

        let response = route_json(
            &server,
            "POST",
            format!("/api/invoices/{invoice_id}/settle"),
            json!({ "payment_preimage": preimage }),
        );
        assert_eq!(response.status, 200);

        let channel_id = bytes32_hex(51);
        let funding_context_id = bytes32_hex(52);
        let spliced_funding_context_id = bytes32_hex(53);
        let response = route_json(
            &server,
            "POST",
            "/api/channels",
            json!({
                "channel_id": channel_id,
                "counterparty_pubkey": channel_peer_pubkey,
                "counterparty_alias": "all-flow-channel-peer",
                "funding_context_id": funding_context_id,
                "local": "100000000",
                "remote": "200000000",
                "sponsor_budget": 1000000,
                "asset": { "kind": "ckb" }
            }),
        );
        assert_eq!(response.status, 200);

        let response = route_json(
            &server,
            "POST",
            format!("/api/channels/{channel_id}/splice"),
            json!({
                "new_funding_epoch": 1,
                "new_funding_context_id": spliced_funding_context_id
            }),
        );
        assert_eq!(response.status, 200);

        let response = route_json(
            &server,
            "POST",
            format!("/api/channels/{channel_id}/publish"),
            json!({
                "funding_context_id": spliced_funding_context_id,
                "state_number": 2
            }),
        );
        assert_eq!(response.status, 200);

        let response = route_empty(
            &server,
            "POST",
            format!("/api/channels/{channel_id}/finalise"),
        );
        assert_eq!(response.status, 200);

        let factory_id = bytes32_hex(61);
        let child_channel_id = bytes32_hex(62);
        let response = route_json(
            &server,
            "POST",
            "/api/factories",
            json!({
                "factory_id": factory_id,
                "participant_pubkeys": [local_pubkey.as_str(), peer_pubkey.as_str()],
                "reserve": "500000000",
                "asset": { "kind": "ckb" }
            }),
        );
        assert_eq!(response.status, 200);

        let response = route_json(
            &server,
            "POST",
            format!("/api/factories/{factory_id}/advance"),
            json!({ "new_update_number": 1 }),
        );
        assert_eq!(response.status, 200);

        let response = route_json(
            &server,
            "POST",
            format!("/api/factories/{factory_id}/materialise-child"),
            json!({
                "child_channel_id": child_channel_id,
                "counterparty_pubkey": peer_pubkey,
                "counterparty_alias": "all-flow-factory-peer",
                "funding_context_id": bytes32_hex(63),
                "local": "100000000",
                "remote": "100000000",
                "sponsor_budget": 1000000,
                "asset": { "kind": "ckb" }
            }),
        );
        assert_eq!(response.status, 200);

        let response = route_empty(&server, "GET", "/api/state");
        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        let missing_flows = body["missing_flows"].as_array().unwrap();
        assert!(
            missing_flows.is_empty(),
            "all required flows should complete, missing {missing_flows:?}"
        );

        let required_flows = body["required_flows"].as_array().unwrap();
        let completed_flows = body["completed_flows"].as_array().unwrap();
        assert_eq!(completed_flows.len(), required_flows.len());
        for flow in required_flows {
            assert!(
                completed_flows.contains(flow),
                "required flow {flow:?} was not completed"
            );
        }
    }

    fn test_server(local_pubkey: &str) -> HubServer {
        test_server_with_options(local_pubkey, None, false, None)
    }

    fn test_server_with_options(
        local_pubkey: &str,
        auth_token: Option<&str>,
        allow_state_restore: bool,
        cors_origin: Option<&str>,
    ) -> HubServer {
        let path = std::env::temp_dir().join(format!(
            "morph-hub-test-{}-{}-{}.json",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            TEST_STATE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_file(&path);
        let store = HubStore::load_or_create(path, local_pubkey, MorphNetwork::Devnet).unwrap();
        HubServer {
            store: Arc::new(Mutex::new(store)),
            ui_dir: PathBuf::from("ui/morph-hub/dist"),
            ckb_rpc_url: None,
            auth_token: auth_token.map(str::to_string),
            allow_state_restore,
            cors_origin: cors_origin.map(str::to_string),
        }
    }

    fn route_json(
        server: &HubServer,
        method: impl Into<String>,
        path: impl Into<String>,
        value: serde_json::Value,
    ) -> HttpResponse {
        route_json_with_headers(
            server,
            method,
            path,
            value,
            std::iter::empty::<(&str, &str)>(),
        )
    }

    fn route_json_with_headers(
        server: &HubServer,
        method: impl Into<String>,
        path: impl Into<String>,
        value: serde_json::Value,
        headers: impl IntoIterator<Item = (&'static str, &'static str)>,
    ) -> HttpResponse {
        server.route(HttpRequest {
            method: method.into(),
            path: path.into(),
            headers: headers
                .into_iter()
                .map(|(key, value)| (key.to_ascii_lowercase(), value.to_string()))
                .collect(),
            body: serde_json::to_vec(&value).unwrap(),
        })
    }

    fn route_empty(
        server: &HubServer,
        method: impl Into<String>,
        path: impl Into<String>,
    ) -> HttpResponse {
        route_empty_with_headers(server, method, path, std::iter::empty::<(&str, &str)>())
    }

    fn route_empty_with_headers(
        server: &HubServer,
        method: impl Into<String>,
        path: impl Into<String>,
        headers: impl IntoIterator<Item = (&'static str, &'static str)>,
    ) -> HttpResponse {
        server.route(request_empty(method, path, headers))
    }

    fn request_empty(
        method: impl Into<String>,
        path: impl Into<String>,
        headers: impl IntoIterator<Item = (&'static str, &'static str)>,
    ) -> HttpRequest {
        HttpRequest {
            method: method.into(),
            path: path.into(),
            headers: headers
                .into_iter()
                .map(|(key, value)| (key.to_ascii_lowercase(), value.to_string()))
                .collect(),
            body: Vec::new(),
        }
    }

    #[cfg(unix)]
    fn state_file_mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn hex_repeat(ch: char) -> String {
        format!("0x{}", ch.to_string().repeat(64))
    }

    fn bytes32_hex(seed: u8) -> String {
        let hex = (0..32)
            .map(|offset| format!("{:02x}", seed.wrapping_add(offset)))
            .collect::<String>();
        format!("0x{hex}")
    }

    fn pubkey_from_scalar(value: u8) -> String {
        let mut bytes = [0u8; 32];
        bytes[31] = value;
        let signing_key = k256::ecdsa::SigningKey::from_bytes((&bytes).into()).unwrap();
        hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes(),
        )
    }
}

fn invoice_status_label(status: MorphInvoiceStatus) -> &'static str {
    match status {
        MorphInvoiceStatus::Open => "open",
        MorphInvoiceStatus::Received => "received",
        MorphInvoiceStatus::Paid => "paid",
        MorphInvoiceStatus::Cancelled => "cancelled",
        MorphInvoiceStatus::Expired => "expired",
    }
}

fn flow_label(flow: MorphBusinessFlow) -> &'static str {
    match flow {
        MorphBusinessFlow::PeerConnected => "peer",
        MorphBusinessFlow::InvoiceCreated => "invoice-created",
        MorphBusinessFlow::InvoiceReceived => "invoice-received",
        MorphBusinessFlow::InvoiceSettled => "invoice-settled",
        MorphBusinessFlow::ChannelOpened => "channel-opened",
        MorphBusinessFlow::StatePublished => "state-published",
        MorphBusinessFlow::ChannelFinalised => "channel-finalised",
        MorphBusinessFlow::ChannelSpliced => "channel-spliced",
        MorphBusinessFlow::FactoryOpened => "factory-opened",
        MorphBusinessFlow::FactoryAdvanced => "factory-advanced",
        MorphBusinessFlow::FactoryChildMaterialised => "factory-child",
    }
}

fn hex_prefixed(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn now_unix() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time is before Unix epoch")?
        .as_secs())
}
