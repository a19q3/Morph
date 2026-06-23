export type Hex32 = `0x${string}`;
export type Pubkey = string;
export type Network = 'devnet' | 'testnet' | 'mainnet';
export type Phase = 'funding' | 'active' | 'settling' | 'closed';
export type InvoiceStatus = 'open' | 'received' | 'paid' | 'cancelled' | 'expired';
export type EventSeverity = 'info' | 'warning' | 'critical';
export type RpcStatus = 'connected' | 'degraded' | 'offline' | 'not_configured';
export type FlowKey =
  | 'peer'
  | 'invoice-created'
  | 'invoice-received'
  | 'invoice-settled'
  | 'channel-opened'
  | 'state-published'
  | 'channel-finalised'
  | 'channel-spliced'
  | 'factory-opened'
  | 'factory-advanced'
  | 'factory-child';

export interface Asset {
  kind: 'ckb' | 'xudt';
  type_hash?: Hex32;
}

export interface Balance {
  asset: Asset;
  local: string;
  remote: string;
  pending: string;
}

export interface PeerRecord {
  pubkey: Pubkey;
  node_id: Hex32;
  alias: string;
}

export interface ChannelRecord {
  channel_id: Hex32;
  counterparty_pubkey: Pubkey;
  counterparty_node_id: Hex32;
  funding_epoch: number;
  funding_context_id: Hex32;
  state_number: number;
  phase: Phase;
  balances: Balance[];
  sponsor_budget: number;
}

export interface InvoiceRecord {
  invoice_id: Hex32;
  encoded_invoice: string;
  status: InvoiceStatus;
  network: Network;
  payee_pubkey?: Pubkey;
  payee_node_id: Hex32;
  channel_id?: Hex32;
  asset: Asset;
  amount: string;
  created_at_unix: number;
  expires_at_unix: number;
  payment_hash: Hex32;
  description: string;
  received_at_unix?: number;
  paid_at_unix?: number;
  cancelled_at_unix?: number;
}

export interface FactoryRecord {
  factory_id: Hex32;
  participant_pubkeys: Pubkey[];
  participant_node_ids: Hex32[];
  update_number: number;
  reserve_balances: Balance[];
  materialised_child_channels: Hex32[];
}

export interface HubEvent {
  id: number;
  severity: EventSeverity;
  event: string;
  subject_id?: Hex32;
  message: string;
  created_at_unix: number;
}

export interface RpcHealth {
  status: RpcStatus;
  url?: string | null;
  tip_height?: number | null;
  chain?: string | null;
  message?: string | null;
}

export interface NodeState {
  pubkey: Pubkey;
  node_id: Hex32;
  network: Network;
  state_path: string;
  rpc: RpcHealth;
  peers: PeerRecord[];
  channels: ChannelRecord[];
  invoices: InvoiceRecord[];
  factories: FactoryRecord[];
  events: HubEvent[];
  required_flows: FlowKey[];
  completed_flows: FlowKey[];
  missing_flows: FlowKey[];
}

export const emptyState: NodeState = {
  pubkey: '',
  node_id: '0x0000000000000000000000000000000000000000000000000000000000000000',
  network: 'devnet',
  state_path: '',
  rpc: { status: 'offline', message: 'API not loaded' },
  peers: [],
  channels: [],
  invoices: [],
  factories: [],
  events: [],
  required_flows: [],
  completed_flows: [],
  missing_flows: [],
};

export function formatAmount(value: string | number | bigint, asset: Asset): string {
  const amount = typeof value === 'bigint' ? value : BigInt(String(value || '0'));
  if (asset.kind === 'ckb') {
    const whole = amount / 100000000n;
    const frac = (amount % 100000000n).toString().padStart(8, '0').replace(/0+$/, '');
    return `${whole}${frac ? `.${frac}` : ''} CKB`;
  }
  return `${amount.toLocaleString()} xUDT`;
}

export function formatBalance(balance?: Balance): string {
  if (!balance) return '0 CKB';
  const total = BigInt(balance.local) + BigInt(balance.remote) + BigInt(balance.pending);
  return formatAmount(total, balance.asset);
}

export function shortHex(value?: string): string {
  if (!value) return '';
  if (value.length <= 18) return value;
  return `${value.slice(0, 10)}...${value.slice(-6)}`;
}

export function assertHex32(value: string, label: string): Hex32 {
  const trimmed = value.trim().toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(trimmed)) {
    throw new Error(`${label} must be a 32-byte 0x-prefixed hex value.`);
  }
  if (/^0x0{64}$/.test(trimmed)) {
    throw new Error(`${label} must not be zero.`);
  }
  return trimmed as Hex32;
}

export function assertPubkey(value: string, label: string): Pubkey {
  const trimmed = value.trim().toLowerCase();
  if (trimmed.startsWith('0x')) {
    throw new Error(`${label} must be 66 hex characters without 0x, matching Fiber RPC convention.`);
  }
  if (!/^[0-9a-f]{66}$/.test(trimmed)) {
    throw new Error(`${label} must be a 33-byte compressed secp256k1 pubkey encoded as 66 hex characters.`);
  }
  if (!/^(02|03)/.test(trimmed)) {
    throw new Error(`${label} must be a compressed secp256k1 pubkey starting with 02 or 03.`);
  }
  return trimmed;
}

export function assertPositiveInteger(value: string, label: string): string {
  const trimmed = value.trim();
  if (!/^[0-9]+$/.test(trimmed)) throw new Error(`${label} must be an unsigned integer.`);
  if (BigInt(trimmed) === 0n) throw new Error(`${label} must be greater than zero.`);
  return trimmed;
}

export function assertNonNegativeInteger(value: string, label: string): string {
  const trimmed = value.trim();
  if (!/^[0-9]+$/.test(trimmed)) throw new Error(`${label} must be an unsigned integer.`);
  return trimmed;
}
