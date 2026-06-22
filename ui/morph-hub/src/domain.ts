import { blake2b } from '@noble/hashes/blake2b';
import { utf8ToBytes } from '@noble/hashes/utils';

export type Hex32 = `0x${string}`;
export type Network = 'devnet' | 'testnet' | 'mainnet';
export type Phase = 'active' | 'settling' | 'closed';
export type InvoiceStatus = 'open' | 'received' | 'paid' | 'cancelled' | 'expired';
export type AlertSeverity = 'info' | 'warning' | 'critical';
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
  typeHash?: Hex32;
}

export interface ChannelRecord {
  channelId: Hex32;
  counterparty: string;
  phase: Phase;
  stateNumber: number;
  fundingEpoch: number;
  fundingContextId: Hex32;
  local: bigint;
  remote: bigint;
  pending: bigint;
  sponsorBudget: bigint;
  asset: Asset;
}

export interface InvoiceRecord {
  invoiceId: Hex32;
  encodedInvoice: string;
  status: InvoiceStatus;
  amount: bigint;
  asset: Asset;
  paymentHash: Hex32;
  description: string;
  createdAtUnix: number;
  expiresAtUnix: number;
  channelId?: Hex32;
}

export interface FactoryRecord {
  factoryId: Hex32;
  updateNumber: number;
  reserve: bigint;
  asset: Asset;
  participants: string[];
  materialisedChildren: Hex32[];
}

export interface WatchtowerAlert {
  id: string;
  severity: AlertSeverity;
  event: string;
  channelId?: Hex32;
  message: string;
  createdAtUnix: number;
}

export interface NodeState {
  nodeId: Hex32;
  network: Network;
  tipHeight: number;
  rpcHealth: 'connected' | 'degraded' | 'offline';
  peers: string[];
  channels: ChannelRecord[];
  invoices: InvoiceRecord[];
  factories: FactoryRecord[];
  watchtowerAlerts: WatchtowerAlert[];
  completedFlows: FlowKey[];
}

export const requiredFlows: FlowKey[] = [
  'peer',
  'invoice-created',
  'invoice-received',
  'invoice-settled',
  'channel-opened',
  'state-published',
  'channel-finalised',
  'channel-spliced',
  'factory-opened',
  'factory-advanced',
  'factory-child',
];

const invoicePrefix = 'morph1';
const invoiceMagic = utf8ToBytes('CKB_MORPH_INVOICE_V1');
const invoiceIdDomain = utf8ToBytes('CKB_MORPH_INVOICE_ID');
const checksumLength = 8;
const ckbPersonal = utf8ToBytes('ckb-default-hash');

export function freshState(): NodeState {
  return {
    nodeId: '0x1111111111111111111111111111111111111111111111111111111111111111',
    network: 'devnet',
    tipHeight: 0,
    rpcHealth: 'connected',
    peers: [],
    channels: [],
    invoices: [],
    factories: [],
    watchtowerAlerts: [],
    completedFlows: [],
  };
}

export function completeFlow(state: NodeState, flow: FlowKey): NodeState {
  if (state.completedFlows.includes(flow)) return state;
  return { ...state, completedFlows: [...state.completedFlows, flow] };
}

export function addAlert(
  state: NodeState,
  alert: Omit<WatchtowerAlert, 'id' | 'createdAtUnix'>
): NodeState {
  return {
    ...state,
    watchtowerAlerts: [
      {
        ...alert,
        id: crypto.randomUUID(),
        createdAtUnix: nowUnix(),
      },
      ...state.watchtowerAlerts,
    ].slice(0, 8),
  };
}

export function createInvoice(input: {
  state: NodeState;
  amount: bigint;
  description: string;
  preimage: Hex32;
  expirySecs: number;
  channelId?: Hex32;
  asset?: Asset;
}): InvoiceRecord {
  const createdAtUnix = nowUnix();
  const expiresAtUnix = createdAtUnix + input.expirySecs;
  const paymentHash = toHex32(ckbHash(hexToBytes(input.preimage)));
  const invoiceWithoutId = {
    network: input.state.network,
    payeeNodeId: input.state.nodeId,
    channelId: input.channelId,
    asset: input.asset ?? ({ kind: 'ckb' } satisfies Asset),
    amount: input.amount,
    createdAtUnix,
    expiresAtUnix,
    paymentHash,
    description: input.description.trim(),
  };
  const invoiceId = deriveInvoiceId(invoiceWithoutId);
  const encodedInvoice = encodeInvoice({ invoiceId, ...invoiceWithoutId });
  return {
    invoiceId,
    encodedInvoice,
    status: 'open',
    amount: input.amount,
    asset: invoiceWithoutId.asset,
    paymentHash,
    description: invoiceWithoutId.description,
    createdAtUnix,
    expiresAtUnix,
    channelId: input.channelId,
  };
}

export function decodeInvoice(encodedInvoice: string): InvoiceRecord {
  const body = encodedInvoice.startsWith(invoicePrefix)
    ? encodedInvoice.slice(invoicePrefix.length)
    : '';
  if (!body || body.length <= checksumLength * 2 || body.length % 2 !== 0) {
    throw new Error('Invalid Morph invoice prefix or length.');
  }
  const payloadHex = body.slice(0, body.length - checksumLength * 2);
  const checksumHex = body.slice(body.length - checksumLength * 2);
  const payload = hexToBytes(`0x${payloadHex}`);
  const checksum = hexToBytes(`0x${checksumHex}`);
  const expected = ckbHash(payload).slice(0, checksumLength);
  if (!bytesEqual(checksum, expected)) {
    throw new Error('Morph invoice checksum mismatch.');
  }
  const cursor = new ByteCursor(payload);
  cursor.expect(invoiceMagic);
  const invoiceId = cursor.readHex32();
  const network = decodeNetwork(cursor.readU8());
  const payeeNodeId = cursor.readHex32();
  const channelId = cursor.readMaybeHex32();
  const asset = cursor.readAsset();
  const amount = cursor.readU128();
  const createdAtUnix = Number(cursor.readU64());
  const expiresAtUnix = Number(cursor.readU64());
  const paymentHash = cursor.readHex32();
  const description = cursor.readString(cursor.readU16());
  cursor.expectEnd();
  const derived = deriveInvoiceId({
    network,
    payeeNodeId,
    channelId,
    asset,
    amount,
    createdAtUnix,
    expiresAtUnix,
    paymentHash,
    description,
  });
  if (derived !== invoiceId) throw new Error('Morph invoice id mismatch.');
  return {
    invoiceId,
    encodedInvoice,
    status: 'open',
    amount,
    asset,
    paymentHash,
    description,
    createdAtUnix,
    expiresAtUnix,
    channelId,
  };
}

export function verifyInvoicePreimage(invoice: InvoiceRecord, preimage: Hex32): boolean {
  return toHex32(ckbHash(hexToBytes(preimage))) === invoice.paymentHash;
}

export function formatAmount(value: bigint, asset: Asset): string {
  if (asset.kind === 'ckb') {
    const whole = value / 100000000n;
    const frac = (value % 100000000n).toString().padStart(8, '0').replace(/0+$/, '');
    return `${whole}${frac ? `.${frac}` : ''} CKB`;
  }
  return `${value.toLocaleString()} xUDT`;
}

export function shortHex(value: string): string {
  if (value.length <= 18) return value;
  return `${value.slice(0, 10)}...${value.slice(-6)}`;
}

export function normaliseHex32(value: string): Hex32 {
  const trimmed = value.trim().toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(trimmed)) {
    throw new Error('Expected a 32-byte 0x-prefixed hex value.');
  }
  return trimmed as Hex32;
}

export function nowUnix(): number {
  return Math.floor(Date.now() / 1000);
}

export function serialiseState(state: NodeState): string {
  return JSON.stringify(
    state,
    (_key, value) => (typeof value === 'bigint' ? value.toString() : value),
    2
  );
}

export function parseState(raw: string): NodeState {
  const parsed = JSON.parse(raw) as NodeState;
  return {
    ...freshState(),
    ...parsed,
    channels: (parsed.channels ?? []).map(channel => ({
      ...channel,
      local: BigInt(channel.local),
      remote: BigInt(channel.remote),
      pending: BigInt(channel.pending),
      sponsorBudget: BigInt(channel.sponsorBudget),
    })),
    invoices: (parsed.invoices ?? []).map(invoice => ({
      ...invoice,
      amount: BigInt(invoice.amount),
    })),
    factories: (parsed.factories ?? []).map(factory => ({
      ...factory,
      reserve: BigInt(factory.reserve),
    })),
  };
}

function encodeInvoice(invoice: {
  invoiceId: Hex32;
  network: Network;
  payeeNodeId: Hex32;
  channelId?: Hex32;
  asset: Asset;
  amount: bigint;
  createdAtUnix: number;
  expiresAtUnix: number;
  paymentHash: Hex32;
  description: string;
}): string {
  const payload = concatBytes(
    invoiceMagic,
    hexToBytes(invoice.invoiceId),
    encodeInvoiceFields(invoice)
  );
  const checksum = ckbHash(payload).slice(0, checksumLength);
  return `${invoicePrefix}${bytesToHex(payload)}${bytesToHex(checksum)}`;
}

function deriveInvoiceId(invoice: {
  network: Network;
  payeeNodeId: Hex32;
  channelId?: Hex32;
  asset: Asset;
  amount: bigint;
  createdAtUnix: number;
  expiresAtUnix: number;
  paymentHash: Hex32;
  description: string;
}): Hex32 {
  return toHex32(ckbHash(concatBytes(invoiceIdDomain, encodeInvoiceFields(invoice))));
}

function encodeInvoiceFields(invoice: {
  network: Network;
  payeeNodeId: Hex32;
  channelId?: Hex32;
  asset: Asset;
  amount: bigint;
  createdAtUnix: number;
  expiresAtUnix: number;
  paymentHash: Hex32;
  description: string;
}): Uint8Array {
  const description = utf8ToBytes(invoice.description);
  return concatBytes(
    Uint8Array.of(encodeNetwork(invoice.network)),
    hexToBytes(invoice.payeeNodeId),
    encodeMaybeHex32(invoice.channelId),
    encodeAsset(invoice.asset),
    leU128(invoice.amount),
    leU64(BigInt(invoice.createdAtUnix)),
    leU64(BigInt(invoice.expiresAtUnix)),
    hexToBytes(invoice.paymentHash),
    leU16(description.length),
    description
  );
}

function ckbHash(bytes: Uint8Array): Uint8Array {
  return blake2b(bytes, { dkLen: 32, personalization: ckbPersonal });
}

function encodeNetwork(network: Network): number {
  if (network === 'devnet') return 1;
  if (network === 'testnet') return 2;
  return 3;
}

function decodeNetwork(value: number): Network {
  if (value === 1) return 'devnet';
  if (value === 2) return 'testnet';
  if (value === 3) return 'mainnet';
  throw new Error('Unknown Morph invoice network.');
}

function encodeAsset(asset: Asset): Uint8Array {
  if (asset.kind === 'ckb') return Uint8Array.of(0);
  return concatBytes(Uint8Array.of(1), hexToBytes(normaliseHex32(asset.typeHash ?? '')));
}

function encodeMaybeHex32(value?: Hex32): Uint8Array {
  return value
    ? concatBytes(Uint8Array.of(1), hexToBytes(value))
    : Uint8Array.of(0);
}

function hexToBytes(value: Hex32): Uint8Array {
  const hex = normaliseHex32(value).slice(2);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function toHex32(bytes: Uint8Array): Hex32 {
  if (bytes.length !== 32) throw new Error('Expected 32 bytes.');
  return `0x${bytesToHex(bytes)}`;
}

function bytesToHex(bytes: Uint8Array): string {
  return [...bytes].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function leU16(value: number): Uint8Array {
  const out = new Uint8Array(2);
  new DataView(out.buffer).setUint16(0, value, true);
  return out;
}

function leU64(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, value, true);
  return out;
}

function leU128(value: bigint): Uint8Array {
  const out = new Uint8Array(16);
  let rest = value;
  for (let i = 0; i < 16; i += 1) {
    out[i] = Number(rest & 0xffn);
    rest >>= 8n;
  }
  return out;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

class ByteCursor {
  private offset = 0;

  constructor(private readonly bytes: Uint8Array) {}

  expect(expected: Uint8Array) {
    const found = this.read(expected.length);
    if (!bytesEqual(found, expected)) throw new Error('Malformed Morph invoice payload.');
  }

  expectEnd() {
    if (this.offset !== this.bytes.length) throw new Error('Trailing Morph invoice bytes.');
  }

  readU8(): number {
    return this.read(1)[0];
  }

  readU16(): number {
    const bytes = this.read(2);
    return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint16(0, true);
  }

  readU64(): bigint {
    const bytes = this.read(8);
    return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getBigUint64(0, true);
  }

  readU128(): bigint {
    const bytes = this.read(16);
    let value = 0n;
    for (let i = 15; i >= 0; i -= 1) value = (value << 8n) + BigInt(bytes[i]);
    return value;
  }

  readHex32(): Hex32 {
    return toHex32(this.read(32));
  }

  readMaybeHex32(): Hex32 | undefined {
    const tag = this.readU8();
    if (tag === 0) return undefined;
    if (tag === 1) return this.readHex32();
    throw new Error('Malformed optional hex field.');
  }

  readAsset(): Asset {
    const tag = this.readU8();
    if (tag === 0) return { kind: 'ckb' };
    if (tag === 1) return { kind: 'xudt', typeHash: this.readHex32() };
    throw new Error('Malformed asset field.');
  }

  readString(len: number): string {
    return new TextDecoder().decode(this.read(len));
  }

  private read(len: number): Uint8Array {
    const end = this.offset + len;
    if (end > this.bytes.length) throw new Error('Unexpected end of invoice payload.');
    const slice = this.bytes.slice(this.offset, end);
    this.offset = end;
    return slice;
  }
}
