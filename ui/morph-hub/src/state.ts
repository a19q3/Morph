import {
  Hex32,
  Balance,
  ChannelRecord,
  FactoryRecord,
  HubEvent,
  InvoiceRecord,
  NodeState,
  PeerRecord,
  WatchtowerAlertRecord,
  assetLabel,
} from './domain';
import { ApiRequestError } from './api';

export type TimeFilter = 'all' | '1h' | '24h' | '7d';
export type LiveMode = 'starting' | 'sse' | 'sse-reconnecting' | 'polling' | 'polling-auth' | 'offline';

export function queryTokens(value: string): string[] {
  return value
    .trim()
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean);
}

export function uniqueStrings(values: string[]): string[] {
  return [...new Set(values.map(value => value.trim()).filter(Boolean))];
}

export function requiredText(value: string, label: string): string {
  const trimmed = value.trim();
  if (!trimmed) throw new Error(`${label} is required.`);
  return trimmed;
}

export function randomHex32(): Hex32 {
  if (typeof crypto === 'undefined' || !crypto.getRandomValues) {
    throw new Error('Secure browser randomness is unavailable.');
  }
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  if (bytes.every(byte => byte === 0)) bytes[31] = 1;
  return `0x${Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')}` as Hex32;
}

export function filterRecords<T>(records: T[], tokens: string[], searchText: (record: T) => string[]): T[] {
  if (tokens.length === 0) return records;
  return records.filter(record => {
    const haystack = searchText(record).join(' ').toLowerCase();
    return tokens.every(token => haystack.includes(token));
  });
}

export function channelSearchText(channel: ChannelRecord): string[] {
  return [
    channel.channel_id,
    channel.factory_id ?? '',
    channel.counterparty_pubkey,
    channel.counterparty_node_id,
    channel.phase,
    channel.funding_context_id,
    String(channel.funding_epoch),
    String(channel.state_number),
    String(channel.sponsor_budget),
    channel.provenance.label,
    channel.provenance.message,
    ...channel.balances.map(balance => `${balance.local} ${balance.remote} ${balance.pending} ${assetLabel(balance.asset)}`),
  ];
}

export function invoiceSearchText(invoice: InvoiceRecord): string[] {
  return [
    invoice.invoice_id,
    invoice.encoded_invoice,
    invoice.status,
    invoice.network,
    invoice.payee_pubkey ?? '',
    invoice.payee_node_id,
    invoice.channel_id ?? '',
    invoice.payment_hash,
    invoice.description,
    invoice.amount,
    assetLabel(invoice.asset),
    invoice.provenance.label,
    invoice.provenance.message,
  ];
}

export function peerSearchText(peer: PeerRecord): string[] {
  return [
    peer.alias,
    peer.pubkey,
    peer.node_id,
    peer.provenance.label,
    peer.provenance.message,
  ];
}

export function factorySearchText(factory: FactoryRecord): string[] {
  return [
    factory.factory_id,
    String(factory.update_number),
    ...factory.participant_pubkeys,
    ...factory.participant_node_ids,
    ...factory.materialised_child_channels,
    factory.provenance.label,
    factory.provenance.message,
    ...factory.reserve_balances.map(balance => `${balance.local} ${balance.remote} ${balance.pending} ${assetLabel(balance.asset)}`),
  ];
}

export function watchtowerAlertSearchText(alert: WatchtowerAlertRecord): string[] {
  return [
    alert.schema,
    alert.channel_id,
    alert.severity,
    alert.event,
    alert.message,
    String(alert.selected_state_number),
    String(alert.observed_state_number ?? ''),
    alert.observed_out_point ?? '',
    alert.publication_tx_hash ?? '',
    alert.selected_funding_anchor ?? '',
    alert.observed_funding_anchor ?? '',
    alert.selected_funding_context_id ?? '',
    alert.observed_funding_context_id ?? '',
    String(alert.scanned_to_block),
    String(alert.next_from_block),
    alert.provenance.label,
    alert.provenance.message,
  ];
}

export function eventSearchText(event: HubEvent): string[] {
  return [
    String(event.id),
    event.severity,
    event.event,
    event.subject_id ?? '',
    event.message,
    String(event.created_at_unix),
    event.provenance.label,
    event.provenance.message,
  ];
}

export function sortInvoicesNewestFirst(invoices: InvoiceRecord[]): InvoiceRecord[] {
  return [...invoices].sort((left, right) => {
    const byCreatedAt = right.created_at_unix - left.created_at_unix;
    return byCreatedAt || right.invoice_id.localeCompare(left.invoice_id);
  });
}

export function newestInvoice(invoices: InvoiceRecord[]): InvoiceRecord | undefined {
  return sortInvoicesNewestFirst(invoices)[0];
}

export function sortEventsNewestFirst(events: HubEvent[]): HubEvent[] {
  return [...events].sort((left, right) => {
    const byId = right.id - left.id;
    return byId || right.created_at_unix - left.created_at_unix;
  });
}

export function sortWatchtowerAlertsNewestFirst(alerts: WatchtowerAlertRecord[]): WatchtowerAlertRecord[] {
  return [...alerts].sort((left, right) => {
    const byCreatedAt = right.created_unix_ms - left.created_unix_ms;
    return byCreatedAt || right.scanned_to_block - left.scanned_to_block || right.channel_id.localeCompare(left.channel_id);
  });
}

export function latestEventId(events: HubEvent[]): number {
  return events.reduce((max, event) => Math.max(max, event.id), 0);
}

export function sortChannelsForOperator(channels: ChannelRecord[], events: HubEvent[]): ChannelRecord[] {
  const eventRank = subjectEventRank(events);
  return [...channels].sort((left, right) => {
    const byEvent = subjectRank(right.channel_id, eventRank) - subjectRank(left.channel_id, eventRank);
    const byPhase = phaseRank(right.phase) - phaseRank(left.phase);
    const byState = right.state_number - left.state_number;
    const byFunding = right.funding_epoch - left.funding_epoch;
    return byEvent || byPhase || byState || byFunding || right.channel_id.localeCompare(left.channel_id);
  });
}

export function sortFactoriesForOperator(factories: FactoryRecord[], events: HubEvent[]): FactoryRecord[] {
  const eventRank = subjectEventRank(events);
  return [...factories].sort((left, right) => {
    const byEvent = subjectRank(right.factory_id, eventRank) - subjectRank(left.factory_id, eventRank);
    const byUpdate = right.update_number - left.update_number;
    const byChildren = right.materialised_child_channels.length - left.materialised_child_channels.length;
    return byEvent || byUpdate || byChildren || right.factory_id.localeCompare(left.factory_id);
  });
}

export function sortPeersForOperator(peers: PeerRecord[], events: HubEvent[]): PeerRecord[] {
  const eventRank = subjectEventRank(events);
  return [...peers].sort((left, right) => {
    const byEvent = subjectRank(right.node_id, eventRank) - subjectRank(left.node_id, eventRank);
    const byAlias = left.alias.localeCompare(right.alias);
    return byEvent || byAlias || left.node_id.localeCompare(right.node_id);
  });
}

export function subjectEventRank(events: HubEvent[]): Map<string, number> {
  const rank = new Map<string, number>();
  events.forEach(event => {
    if (!event.subject_id) return;
    const subject = event.subject_id.toLowerCase();
    rank.set(subject, Math.max(rank.get(subject) ?? 0, event.id));
  });
  return rank;
}

export function subjectRank(subjectId: string, eventRank: Map<string, number>): number {
  return eventRank.get(subjectId.toLowerCase()) ?? 0;
}

export function phaseRank(phase: ChannelRecord['phase']): number {
  if (phase === 'active') return 4;
  if (phase === 'settling') return 3;
  if (phase === 'funding') return 2;
  if (phase === 'closed') return 1;
  return 0;
}

export async function copyTextToClipboard(text: string): Promise<void> {
  let clipboardError: unknown;
  if (navigator.clipboard?.writeText && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text);
      return;
    } catch (err) {
      clipboardError = err;
    }
  }

  const textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.setAttribute('readonly', '');
  textarea.style.position = 'fixed';
  textarea.style.left = '-9999px';
  textarea.style.top = '0';
  document.body.appendChild(textarea);
  textarea.focus();
  textarea.select();
  try {
    if (!document.execCommand('copy')) {
      throw new Error('clipboard copy was rejected');
    }
  } catch (err) {
    throw clipboardError instanceof Error ? clipboardError : err;
  } finally {
    document.body.removeChild(textarea);
  }
}

export function balanceTotal(balance?: Balance): bigint {
  if (!balance) return 0n;
  return BigInt(balance.local) + BigInt(balance.remote) + BigInt(balance.pending);
}

export function invoiceExpiryLabel(expiresAtUnix: number, nowMs: number): string {
  const remainingSeconds = Math.floor(expiresAtUnix - nowMs / 1_000);
  if (remainingSeconds <= 0) return 'expired';
  if (remainingSeconds < 60) return `expires in ${remainingSeconds}s`;
  const remainingMinutes = Math.floor(remainingSeconds / 60);
  if (remainingMinutes < 60) return `expires in ${remainingMinutes}m`;
  const remainingHours = Math.floor(remainingMinutes / 60);
  if (remainingHours < 48) return `expires in ${remainingHours}h`;
  return `expires in ${Math.floor(remainingHours / 24)}d`;
}

export function rpcTone(status: NodeState['rpc']['status']): 'good' | 'neutral' | 'warn' | 'bad' {
  if (status === 'connected') return 'good';
  if (status === 'not_configured') return 'neutral';
  if (status === 'degraded') return 'warn';
  return 'bad';
}

export function rpcLabel(state: NodeState): string {
  if (state.rpc.status === 'not_configured') return 'rpc not configured';
  if (state.rpc.status === 'connected') return state.rpc.chain ? `${state.rpc.chain} connected` : 'rpc connected';
  if (state.rpc.message) return `${state.rpc.status}: ${compactMessage(state.rpc.message, 48)}`;
  return state.rpc.status;
}

export function rpcDetail(state: NodeState): string {
  const parts = [rpcLabel(state)];
  if (state.rpc.url) parts.push(state.rpc.url);
  if (state.rpc.tip_height != null) parts.push(`tip ${state.rpc.tip_height}`);
  if (state.rpc.message && !parts.includes(state.rpc.message)) parts.push(state.rpc.message);
  return parts.join(' · ');
}

export function compactMessage(message: string, maxLength: number): string {
  const compact = message.replace(/\s+/g, ' ').trim();
  if (compact.length <= maxLength) return compact;
  return `${compact.slice(0, maxLength - 1)}…`;
}

export function formatActionError(label: string, err: unknown): string {
  const message = err instanceof Error ? err.message : String(err);
  const retry = err instanceof ApiRequestError && err.retryAfterSeconds != null
    ? ` Try again in ${err.retryAfterSeconds} seconds.`
    : '';
  return `${label} failed: ${message}${retry}`;
}

export function liveTone(mode: LiveMode): 'good' | 'neutral' | 'warn' | 'bad' {
  if (mode === 'sse' || mode === 'polling-auth') return 'good';
  if (mode === 'polling') return 'neutral';
  if (mode === 'sse-reconnecting' || mode === 'starting') return 'warn';
  return 'bad';
}

export function liveLabel(mode: LiveMode): string {
  switch (mode) {
    case 'sse':
      return 'live sse';
    case 'sse-reconnecting':
      return 'live reconnecting';
    case 'polling-auth':
      return 'live polling auth';
    case 'polling':
      return 'live polling';
    case 'offline':
      return 'live offline';
    case 'starting':
      return 'live starting';
  }
}

export function lastRefreshLabel(lastRefreshMs: number | null, nowMs: number): string {
  if (lastRefreshMs == null) return 'not refreshed yet';
  const elapsedSecs = Math.max(0, Math.floor((nowMs - lastRefreshMs) / 1000));
  if (elapsedSecs < 2) return 'refreshed just now';
  if (elapsedSecs < 60) return `refreshed ${elapsedSecs}s ago`;
  const elapsedMins = Math.floor(elapsedSecs / 60);
  if (elapsedMins < 60) return `refreshed ${elapsedMins}m ago`;
  return `refreshed ${Math.floor(elapsedMins / 60)}h ago`;
}

export function withinTimeWindow(timestampMs: number, filter: TimeFilter): boolean {
  if (filter === 'all') return true;
  const ageMs = Date.now() - timestampMs;
  if (ageMs < 0) return true;
  switch (filter) {
    case '1h':
      return ageMs <= 60 * 60 * 1000;
    case '24h':
      return ageMs <= 24 * 60 * 60 * 1000;
    case '7d':
      return ageMs <= 7 * 24 * 60 * 60 * 1000;
  }
}

export function isAuthTokenError(message: string): boolean {
  return message.toLowerCase().includes('morph hub auth token');
}
