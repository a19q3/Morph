use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::hash::blake2b256;
use crate::types::{Amount, Bytes32, Capacity, Phase};

const INVOICE_PAYLOAD_MAGIC: &[u8] = b"CKB_MORPH_INVOICE_V1";
const INVOICE_ID_DOMAIN: &[u8] = b"CKB_MORPH_INVOICE_ID";
const INVOICE_PREFIX: &str = "morph1";
const INVOICE_CHECKSUM_LEN: usize = 8;
const MAX_INVOICE_DESCRIPTION_LEN: usize = 280;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NodeError {
    #[error("node id must not be zero")]
    ZeroNodeId,
    #[error("identifier must not be zero")]
    ZeroIdentifier,
    #[error("amount must be greater than zero")]
    ZeroAmount,
    #[error("invoice expiry must be later than creation time")]
    InvoiceExpiryNotAfterCreation,
    #[error("invoice description is too long")]
    InvoiceDescriptionTooLong,
    #[error("invoice has an unsupported prefix")]
    InvoicePrefixMismatch,
    #[error("invoice hex payload is invalid")]
    InvoiceHexInvalid,
    #[error("invoice checksum mismatch")]
    InvoiceChecksumMismatch,
    #[error("invoice payload is malformed")]
    InvoicePayloadMalformed,
    #[error("invoice id does not match its canonical fields")]
    InvoiceIdMismatch,
    #[error("invoice has expired")]
    InvoiceExpired,
    #[error("invoice is not open")]
    InvoiceNotOpen,
    #[error("payment preimage does not match invoice hash")]
    InvoicePreimageMismatch,
    #[error("invoice already exists")]
    InvoiceAlreadyExists,
    #[error("invoice was not found")]
    InvoiceNotFound,
    #[error("peer was not found")]
    PeerNotFound,
    #[error("peer already exists")]
    PeerAlreadyExists,
    #[error("channel already exists")]
    ChannelAlreadyExists,
    #[error("channel was not found")]
    ChannelNotFound,
    #[error("channel is not active")]
    ChannelNotActive,
    #[error("channel is not settling")]
    ChannelNotSettling,
    #[error("state number must advance")]
    StateNumberNotAdvanced,
    #[error("funding epoch must advance")]
    FundingEpochNotAdvanced,
    #[error("funding context must change")]
    FundingContextUnchanged,
    #[error("published state uses the wrong funding context")]
    FundingContextMismatch,
    #[error("factory already exists")]
    FactoryAlreadyExists,
    #[error("factory was not found")]
    FactoryNotFound,
    #[error("factory update number must advance")]
    FactoryUpdateNotAdvanced,
    #[error("factory child channel id is already in use")]
    FactoryChildAlreadyMaterialised,
    #[error("asset balance total overflow")]
    AssetBalanceOverflow,
}

pub type NodeResult<T> = std::result::Result<T, NodeError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MorphNetwork {
    Devnet,
    Testnet,
    Mainnet,
}

impl MorphNetwork {
    const fn as_u8(self) -> u8 {
        match self {
            Self::Devnet => 1,
            Self::Testnet => 2,
            Self::Mainnet => 3,
        }
    }

    const fn from_u8(value: u8) -> NodeResult<Self> {
        match value {
            1 => Ok(Self::Devnet),
            2 => Ok(Self::Testnet),
            3 => Ok(Self::Mainnet),
            _ => Err(NodeError::InvoicePayloadMalformed),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MorphAsset {
    Ckb,
    Xudt(Bytes32),
}

impl MorphAsset {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Ckb => out.push(0),
            Self::Xudt(type_hash) => {
                out.push(1);
                out.extend_from_slice(type_hash);
            }
        }
    }

    fn decode(cursor: &mut ByteCursor<'_>) -> NodeResult<Self> {
        match cursor.read_u8()? {
            0 => Ok(Self::Ckb),
            1 => Ok(Self::Xudt(cursor.read_bytes32()?)),
            _ => Err(NodeError::InvoicePayloadMalformed),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MorphInvoice {
    pub invoice_id: Bytes32,
    pub network: MorphNetwork,
    pub payee_node_id: Bytes32,
    pub channel_id: Option<Bytes32>,
    pub asset: MorphAsset,
    pub amount: Amount,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub payment_hash: Bytes32,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewMorphInvoice {
    pub network: MorphNetwork,
    pub payee_node_id: Bytes32,
    pub channel_id: Option<Bytes32>,
    pub asset: MorphAsset,
    pub amount: Amount,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub payment_preimage: Option<Bytes32>,
    pub payment_hash: Option<Bytes32>,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MorphInvoiceStatus {
    Open,
    Received,
    Paid,
    Cancelled,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredMorphInvoice {
    pub invoice: MorphInvoice,
    pub encoded_invoice: String,
    pub status: MorphInvoiceStatus,
    pub received_at_unix: Option<u64>,
    pub paid_at_unix: Option<u64>,
    pub cancelled_at_unix: Option<u64>,
    pub payment_preimage: Option<Bytes32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MorphInvoiceBook {
    invoices: BTreeMap<Bytes32, StoredMorphInvoice>,
}

impl MorphInvoice {
    pub fn new(request: NewMorphInvoice) -> NodeResult<Self> {
        validate_bytes32_nonzero(&request.payee_node_id, NodeError::ZeroNodeId)?;
        if let Some(channel_id) = request.channel_id {
            validate_bytes32_nonzero(&channel_id, NodeError::ZeroIdentifier)?;
        }
        if request.amount == 0 {
            return Err(NodeError::ZeroAmount);
        }
        if request.expires_at_unix <= request.created_at_unix {
            return Err(NodeError::InvoiceExpiryNotAfterCreation);
        }
        if request.description.len() > MAX_INVOICE_DESCRIPTION_LEN {
            return Err(NodeError::InvoiceDescriptionTooLong);
        }
        let payment_hash = match (request.payment_preimage, request.payment_hash) {
            (Some(preimage), None) => blake2b256(&preimage),
            (None, Some(hash)) => hash,
            (Some(_), Some(_)) | (None, None) => return Err(NodeError::InvoicePayloadMalformed),
        };
        validate_bytes32_nonzero(&payment_hash, NodeError::ZeroIdentifier)?;

        let mut invoice = Self {
            invoice_id: [0u8; 32],
            network: request.network,
            payee_node_id: request.payee_node_id,
            channel_id: request.channel_id,
            asset: request.asset,
            amount: request.amount,
            created_at_unix: request.created_at_unix,
            expires_at_unix: request.expires_at_unix,
            payment_hash,
            description: request.description,
        };
        invoice.invoice_id = invoice.derived_invoice_id();
        Ok(invoice)
    }

    pub fn encode(&self) -> String {
        let payload = self.payload_bytes();
        let checksum = invoice_checksum(&payload);
        format!(
            "{INVOICE_PREFIX}{}{}",
            hex::encode(payload),
            hex::encode(checksum)
        )
    }

    pub fn decode(encoded: &str) -> NodeResult<Self> {
        let body = encoded
            .strip_prefix(INVOICE_PREFIX)
            .ok_or(NodeError::InvoicePrefixMismatch)?;
        if body.len() <= INVOICE_CHECKSUM_LEN * 2 || body.len() % 2 != 0 {
            return Err(NodeError::InvoiceHexInvalid);
        }
        let split_at = body.len() - INVOICE_CHECKSUM_LEN * 2;
        let payload = hex::decode(&body[..split_at]).map_err(|_| NodeError::InvoiceHexInvalid)?;
        let checksum = hex::decode(&body[split_at..]).map_err(|_| NodeError::InvoiceHexInvalid)?;
        if checksum != invoice_checksum(&payload) {
            return Err(NodeError::InvoiceChecksumMismatch);
        }
        let invoice = Self::from_payload_bytes(&payload)?;
        if invoice.invoice_id != invoice.derived_invoice_id() {
            return Err(NodeError::InvoiceIdMismatch);
        }
        invoice.validate()?;
        Ok(invoice)
    }

    pub fn validate(&self) -> NodeResult<()> {
        validate_bytes32_nonzero(&self.payee_node_id, NodeError::ZeroNodeId)?;
        validate_bytes32_nonzero(&self.invoice_id, NodeError::ZeroIdentifier)?;
        validate_bytes32_nonzero(&self.payment_hash, NodeError::ZeroIdentifier)?;
        if let Some(channel_id) = self.channel_id {
            validate_bytes32_nonzero(&channel_id, NodeError::ZeroIdentifier)?;
        }
        if self.amount == 0 {
            return Err(NodeError::ZeroAmount);
        }
        if self.expires_at_unix <= self.created_at_unix {
            return Err(NodeError::InvoiceExpiryNotAfterCreation);
        }
        if self.description.len() > MAX_INVOICE_DESCRIPTION_LEN {
            return Err(NodeError::InvoiceDescriptionTooLong);
        }
        if self.invoice_id != self.derived_invoice_id() {
            return Err(NodeError::InvoiceIdMismatch);
        }
        Ok(())
    }

    pub fn is_expired_at(&self, now_unix: u64) -> bool {
        now_unix >= self.expires_at_unix
    }

    pub fn verify_preimage(&self, payment_preimage: &Bytes32) -> NodeResult<()> {
        if blake2b256(payment_preimage) != self.payment_hash {
            return Err(NodeError::InvoicePreimageMismatch);
        }
        Ok(())
    }

    fn derived_invoice_id(&self) -> Bytes32 {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(INVOICE_ID_DOMAIN);
        self.encode_fields_without_invoice_id(&mut bytes);
        blake2b256(&bytes)
    }

    fn payload_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(INVOICE_PAYLOAD_MAGIC);
        bytes.extend_from_slice(&self.invoice_id);
        self.encode_fields_without_invoice_id(&mut bytes);
        bytes
    }

    fn encode_fields_without_invoice_id(&self, out: &mut Vec<u8>) {
        out.push(self.network.as_u8());
        out.extend_from_slice(&self.payee_node_id);
        encode_option_bytes32(self.channel_id, out);
        self.asset.encode(out);
        out.extend_from_slice(&self.amount.to_le_bytes());
        out.extend_from_slice(&self.created_at_unix.to_le_bytes());
        out.extend_from_slice(&self.expires_at_unix.to_le_bytes());
        out.extend_from_slice(&self.payment_hash);
        let description = self.description.as_bytes();
        out.extend_from_slice(&(description.len() as u16).to_le_bytes());
        out.extend_from_slice(description);
    }

    fn from_payload_bytes(payload: &[u8]) -> NodeResult<Self> {
        if !payload.starts_with(INVOICE_PAYLOAD_MAGIC) {
            return Err(NodeError::InvoicePayloadMalformed);
        }
        let mut cursor = ByteCursor::new(&payload[INVOICE_PAYLOAD_MAGIC.len()..]);
        let invoice_id = cursor.read_bytes32()?;
        let network = MorphNetwork::from_u8(cursor.read_u8()?)?;
        let payee_node_id = cursor.read_bytes32()?;
        let channel_id = decode_option_bytes32(&mut cursor)?;
        let asset = MorphAsset::decode(&mut cursor)?;
        let amount = cursor.read_u128()?;
        let created_at_unix = cursor.read_u64()?;
        let expires_at_unix = cursor.read_u64()?;
        let payment_hash = cursor.read_bytes32()?;
        let description_len = cursor.read_u16()? as usize;
        let description = cursor.read_string(description_len)?;
        if !cursor.is_empty() {
            return Err(NodeError::InvoicePayloadMalformed);
        }
        Ok(Self {
            invoice_id,
            network,
            payee_node_id,
            channel_id,
            asset,
            amount,
            created_at_unix,
            expires_at_unix,
            payment_hash,
            description,
        })
    }
}

impl MorphInvoiceBook {
    pub fn records(&self) -> impl Iterator<Item = &StoredMorphInvoice> {
        self.invoices.values()
    }

    pub fn insert_stored(&mut self, stored: StoredMorphInvoice) -> NodeResult<()> {
        stored.invoice.validate()?;
        if stored.encoded_invoice != stored.invoice.encode() {
            return Err(NodeError::InvoiceIdMismatch);
        }
        if self.invoices.contains_key(&stored.invoice.invoice_id) {
            return Err(NodeError::InvoiceAlreadyExists);
        }
        self.invoices.insert(stored.invoice.invoice_id, stored);
        Ok(())
    }

    pub fn create_invoice(&mut self, request: NewMorphInvoice) -> NodeResult<StoredMorphInvoice> {
        let preimage = request.payment_preimage;
        let invoice = MorphInvoice::new(request)?;
        let encoded_invoice = invoice.encode();
        if self.invoices.contains_key(&invoice.invoice_id) {
            return Err(NodeError::InvoiceAlreadyExists);
        }
        let stored = StoredMorphInvoice {
            invoice: invoice.clone(),
            encoded_invoice,
            status: MorphInvoiceStatus::Open,
            received_at_unix: None,
            paid_at_unix: None,
            cancelled_at_unix: None,
            payment_preimage: preimage,
        };
        self.invoices.insert(invoice.invoice_id, stored.clone());
        Ok(stored)
    }

    pub fn insert_decoded(&mut self, encoded_invoice: &str) -> NodeResult<StoredMorphInvoice> {
        let invoice = MorphInvoice::decode(encoded_invoice)?;
        if self.invoices.contains_key(&invoice.invoice_id) {
            return Err(NodeError::InvoiceAlreadyExists);
        }
        let stored = StoredMorphInvoice {
            invoice: invoice.clone(),
            encoded_invoice: encoded_invoice.to_string(),
            status: MorphInvoiceStatus::Open,
            received_at_unix: None,
            paid_at_unix: None,
            cancelled_at_unix: None,
            payment_preimage: None,
        };
        self.invoices.insert(invoice.invoice_id, stored.clone());
        Ok(stored)
    }

    pub fn get(&self, invoice_id: &Bytes32) -> NodeResult<&StoredMorphInvoice> {
        self.invoices
            .get(invoice_id)
            .ok_or(NodeError::InvoiceNotFound)
    }

    pub fn receive(&mut self, invoice_id: &Bytes32, now_unix: u64) -> NodeResult<()> {
        let stored = self
            .invoices
            .get_mut(invoice_id)
            .ok_or(NodeError::InvoiceNotFound)?;
        ensure_invoice_open(stored, now_unix)?;
        stored.status = MorphInvoiceStatus::Received;
        stored.received_at_unix = Some(now_unix);
        Ok(())
    }

    pub fn settle(
        &mut self,
        invoice_id: &Bytes32,
        payment_preimage: Bytes32,
        now_unix: u64,
    ) -> NodeResult<()> {
        let stored = self
            .invoices
            .get_mut(invoice_id)
            .ok_or(NodeError::InvoiceNotFound)?;
        if stored.status != MorphInvoiceStatus::Open
            && stored.status != MorphInvoiceStatus::Received
        {
            return Err(NodeError::InvoiceNotOpen);
        }
        if stored.invoice.is_expired_at(now_unix) {
            stored.status = MorphInvoiceStatus::Expired;
            return Err(NodeError::InvoiceExpired);
        }
        stored.invoice.verify_preimage(&payment_preimage)?;
        stored.status = MorphInvoiceStatus::Paid;
        stored.paid_at_unix = Some(now_unix);
        stored.payment_preimage = Some(payment_preimage);
        Ok(())
    }

    pub fn cancel(&mut self, invoice_id: &Bytes32, now_unix: u64) -> NodeResult<()> {
        let stored = self
            .invoices
            .get_mut(invoice_id)
            .ok_or(NodeError::InvoiceNotFound)?;
        ensure_invoice_open(stored, now_unix)?;
        stored.status = MorphInvoiceStatus::Cancelled;
        stored.cancelled_at_unix = Some(now_unix);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MorphPeer {
    pub node_id: Bytes32,
    pub alias: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MorphAssetBalance {
    pub asset: MorphAsset,
    pub local: Amount,
    pub remote: Amount,
    pub pending: Amount,
}

impl MorphAssetBalance {
    pub fn total(&self) -> NodeResult<Amount> {
        self.local
            .checked_add(self.remote)
            .and_then(|value| value.checked_add(self.pending))
            .ok_or(NodeError::AssetBalanceOverflow)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MorphChannelRecord {
    pub channel_id: Bytes32,
    pub counterparty_node_id: Bytes32,
    pub funding_epoch: u64,
    pub funding_context_id: Bytes32,
    pub state_number: u64,
    pub phase: Phase,
    pub balances: Vec<MorphAssetBalance>,
    pub sponsor_budget: Capacity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MorphFactoryRecord {
    pub factory_id: Bytes32,
    pub participant_node_ids: BTreeSet<Bytes32>,
    pub update_number: u64,
    pub reserve_balances: Vec<MorphAssetBalance>,
    pub materialised_child_channels: BTreeSet<Bytes32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MorphBusinessFlow {
    PeerConnected,
    InvoiceCreated,
    InvoiceReceived,
    InvoiceSettled,
    ChannelOpened,
    StatePublished,
    ChannelFinalised,
    ChannelSpliced,
    FactoryOpened,
    FactoryAdvanced,
    FactoryChildMaterialised,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MorphNodeState {
    pub node_id: Bytes32,
    pub network: MorphNetwork,
    pub peers: BTreeMap<Bytes32, MorphPeer>,
    pub channels: BTreeMap<Bytes32, MorphChannelRecord>,
    pub factories: BTreeMap<Bytes32, MorphFactoryRecord>,
    pub invoices: MorphInvoiceBook,
    pub completed_flows: BTreeSet<MorphBusinessFlow>,
}

impl MorphNodeState {
    pub fn new(node_id: Bytes32, network: MorphNetwork) -> NodeResult<Self> {
        validate_bytes32_nonzero(&node_id, NodeError::ZeroNodeId)?;
        Ok(Self {
            node_id,
            network,
            peers: BTreeMap::new(),
            channels: BTreeMap::new(),
            factories: BTreeMap::new(),
            invoices: MorphInvoiceBook::default(),
            completed_flows: BTreeSet::new(),
        })
    }

    pub fn required_business_flows() -> BTreeSet<MorphBusinessFlow> {
        BTreeSet::from([
            MorphBusinessFlow::PeerConnected,
            MorphBusinessFlow::InvoiceCreated,
            MorphBusinessFlow::InvoiceReceived,
            MorphBusinessFlow::InvoiceSettled,
            MorphBusinessFlow::ChannelOpened,
            MorphBusinessFlow::StatePublished,
            MorphBusinessFlow::ChannelFinalised,
            MorphBusinessFlow::ChannelSpliced,
            MorphBusinessFlow::FactoryOpened,
            MorphBusinessFlow::FactoryAdvanced,
            MorphBusinessFlow::FactoryChildMaterialised,
        ])
    }

    pub fn missing_business_flows(&self) -> BTreeSet<MorphBusinessFlow> {
        Self::required_business_flows()
            .difference(&self.completed_flows)
            .copied()
            .collect()
    }

    pub fn connect_peer(&mut self, peer: MorphPeer) -> NodeResult<()> {
        validate_bytes32_nonzero(&peer.node_id, NodeError::ZeroNodeId)?;
        if self.peers.contains_key(&peer.node_id) {
            return Err(NodeError::PeerAlreadyExists);
        }
        self.peers.insert(peer.node_id, peer);
        self.completed_flows
            .insert(MorphBusinessFlow::PeerConnected);
        Ok(())
    }

    pub fn create_invoice(
        &mut self,
        mut request: NewMorphInvoice,
    ) -> NodeResult<StoredMorphInvoice> {
        request.network = self.network;
        request.payee_node_id = self.node_id;
        let stored = self.invoices.create_invoice(request)?;
        self.completed_flows
            .insert(MorphBusinessFlow::InvoiceCreated);
        Ok(stored)
    }

    pub fn receive_invoice(&mut self, invoice_id: &Bytes32, now_unix: u64) -> NodeResult<()> {
        self.invoices.receive(invoice_id, now_unix)?;
        self.completed_flows
            .insert(MorphBusinessFlow::InvoiceReceived);
        Ok(())
    }

    pub fn settle_invoice(
        &mut self,
        invoice_id: &Bytes32,
        payment_preimage: Bytes32,
        now_unix: u64,
    ) -> NodeResult<()> {
        self.invoices
            .settle(invoice_id, payment_preimage, now_unix)?;
        self.completed_flows
            .insert(MorphBusinessFlow::InvoiceSettled);
        Ok(())
    }

    pub fn open_channel(&mut self, channel: MorphChannelRecord) -> NodeResult<()> {
        validate_channel_record(&channel)?;
        if !self.peers.contains_key(&channel.counterparty_node_id) {
            return Err(NodeError::PeerNotFound);
        }
        if self.channels.contains_key(&channel.channel_id) {
            return Err(NodeError::ChannelAlreadyExists);
        }
        self.channels.insert(channel.channel_id, channel);
        self.completed_flows
            .insert(MorphBusinessFlow::ChannelOpened);
        Ok(())
    }

    pub fn publish_state(
        &mut self,
        channel_id: &Bytes32,
        funding_context_id: Bytes32,
        state_number: u64,
    ) -> NodeResult<()> {
        let channel = self
            .channels
            .get_mut(channel_id)
            .ok_or(NodeError::ChannelNotFound)?;
        if channel.phase != Phase::Active && channel.phase != Phase::Settling {
            return Err(NodeError::ChannelNotActive);
        }
        if funding_context_id != channel.funding_context_id {
            return Err(NodeError::FundingContextMismatch);
        }
        if state_number <= channel.state_number {
            return Err(NodeError::StateNumberNotAdvanced);
        }
        channel.state_number = state_number;
        channel.phase = Phase::Settling;
        self.completed_flows
            .insert(MorphBusinessFlow::StatePublished);
        Ok(())
    }

    pub fn finalise_channel(&mut self, channel_id: &Bytes32) -> NodeResult<()> {
        let channel = self
            .channels
            .get_mut(channel_id)
            .ok_or(NodeError::ChannelNotFound)?;
        if channel.phase != Phase::Settling {
            return Err(NodeError::ChannelNotSettling);
        }
        channel.phase = Phase::Closed;
        self.completed_flows
            .insert(MorphBusinessFlow::ChannelFinalised);
        Ok(())
    }

    pub fn splice_channel(
        &mut self,
        channel_id: &Bytes32,
        new_funding_epoch: u64,
        new_funding_context_id: Bytes32,
    ) -> NodeResult<()> {
        validate_bytes32_nonzero(&new_funding_context_id, NodeError::ZeroIdentifier)?;
        let channel = self
            .channels
            .get_mut(channel_id)
            .ok_or(NodeError::ChannelNotFound)?;
        if channel.phase != Phase::Active {
            return Err(NodeError::ChannelNotActive);
        }
        if new_funding_epoch <= channel.funding_epoch {
            return Err(NodeError::FundingEpochNotAdvanced);
        }
        if new_funding_context_id == channel.funding_context_id {
            return Err(NodeError::FundingContextUnchanged);
        }
        channel.funding_epoch = new_funding_epoch;
        channel.funding_context_id = new_funding_context_id;
        self.completed_flows
            .insert(MorphBusinessFlow::ChannelSpliced);
        Ok(())
    }

    pub fn open_factory(&mut self, factory: MorphFactoryRecord) -> NodeResult<()> {
        validate_bytes32_nonzero(&factory.factory_id, NodeError::ZeroIdentifier)?;
        if factory.participant_node_ids.is_empty()
            || factory
                .participant_node_ids
                .iter()
                .any(|node_id| is_zero_bytes32(node_id))
        {
            return Err(NodeError::ZeroNodeId);
        }
        if self.factories.contains_key(&factory.factory_id) {
            return Err(NodeError::FactoryAlreadyExists);
        }
        self.factories.insert(factory.factory_id, factory);
        self.completed_flows
            .insert(MorphBusinessFlow::FactoryOpened);
        Ok(())
    }

    pub fn advance_factory(
        &mut self,
        factory_id: &Bytes32,
        new_update_number: u64,
    ) -> NodeResult<()> {
        let factory = self
            .factories
            .get_mut(factory_id)
            .ok_or(NodeError::FactoryNotFound)?;
        if new_update_number <= factory.update_number {
            return Err(NodeError::FactoryUpdateNotAdvanced);
        }
        factory.update_number = new_update_number;
        self.completed_flows
            .insert(MorphBusinessFlow::FactoryAdvanced);
        Ok(())
    }

    pub fn materialise_child_channel(
        &mut self,
        factory_id: &Bytes32,
        child: MorphChannelRecord,
    ) -> NodeResult<()> {
        validate_channel_record(&child)?;
        if !self.peers.contains_key(&child.counterparty_node_id) {
            return Err(NodeError::PeerNotFound);
        }
        if self.channels.contains_key(&child.channel_id) {
            return Err(NodeError::ChannelAlreadyExists);
        }
        let factory = self
            .factories
            .get_mut(factory_id)
            .ok_or(NodeError::FactoryNotFound)?;
        if !factory.materialised_child_channels.insert(child.channel_id) {
            return Err(NodeError::FactoryChildAlreadyMaterialised);
        }
        self.channels.insert(child.channel_id, child);
        self.completed_flows
            .insert(MorphBusinessFlow::FactoryChildMaterialised);
        Ok(())
    }
}

fn validate_channel_record(channel: &MorphChannelRecord) -> NodeResult<()> {
    validate_bytes32_nonzero(&channel.channel_id, NodeError::ZeroIdentifier)?;
    validate_bytes32_nonzero(&channel.counterparty_node_id, NodeError::ZeroNodeId)?;
    validate_bytes32_nonzero(&channel.funding_context_id, NodeError::ZeroIdentifier)?;
    for balance in &channel.balances {
        balance.total()?;
    }
    Ok(())
}

fn ensure_invoice_open(stored: &mut StoredMorphInvoice, now_unix: u64) -> NodeResult<()> {
    if stored.status != MorphInvoiceStatus::Open {
        return Err(NodeError::InvoiceNotOpen);
    }
    if stored.invoice.is_expired_at(now_unix) {
        stored.status = MorphInvoiceStatus::Expired;
        return Err(NodeError::InvoiceExpired);
    }
    Ok(())
}

fn validate_bytes32_nonzero(value: &Bytes32, error: NodeError) -> NodeResult<()> {
    if is_zero_bytes32(value) {
        return Err(error);
    }
    Ok(())
}

fn is_zero_bytes32(value: &Bytes32) -> bool {
    value.iter().all(|byte| *byte == 0)
}

fn invoice_checksum(payload: &[u8]) -> [u8; INVOICE_CHECKSUM_LEN] {
    let digest = blake2b256(payload);
    let mut checksum = [0u8; INVOICE_CHECKSUM_LEN];
    checksum.copy_from_slice(&digest[..INVOICE_CHECKSUM_LEN]);
    checksum
}

fn encode_option_bytes32(value: Option<Bytes32>, out: &mut Vec<u8>) {
    match value {
        Some(bytes) => {
            out.push(1);
            out.extend_from_slice(&bytes);
        }
        None => out.push(0),
    }
}

fn decode_option_bytes32(cursor: &mut ByteCursor<'_>) -> NodeResult<Option<Bytes32>> {
    match cursor.read_u8()? {
        0 => Ok(None),
        1 => Ok(Some(cursor.read_bytes32()?)),
        _ => Err(NodeError::InvoicePayloadMalformed),
    }
}

struct ByteCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ByteCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn read_u8(&mut self) -> NodeResult<u8> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_u16(&mut self) -> NodeResult<u16> {
        let bytes = self.read_exact(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn read_u64(&mut self) -> NodeResult<u64> {
        let bytes = self.read_exact(8)?;
        let mut raw = [0u8; 8];
        raw.copy_from_slice(bytes);
        Ok(u64::from_le_bytes(raw))
    }

    fn read_u128(&mut self) -> NodeResult<u128> {
        let bytes = self.read_exact(16)?;
        let mut raw = [0u8; 16];
        raw.copy_from_slice(bytes);
        Ok(u128::from_le_bytes(raw))
    }

    fn read_bytes32(&mut self) -> NodeResult<Bytes32> {
        let bytes = self.read_exact(32)?;
        let mut raw = [0u8; 32];
        raw.copy_from_slice(bytes);
        Ok(raw)
    }

    fn read_string(&mut self, len: usize) -> NodeResult<String> {
        let bytes = self.read_exact(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| NodeError::InvoicePayloadMalformed)
    }

    fn read_exact(&mut self, len: usize) -> NodeResult<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(NodeError::InvoicePayloadMalformed)?;
        if end > self.bytes.len() {
            return Err(NodeError::InvoicePayloadMalformed);
        }
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }
}
