import { Activity, AlertTriangle, BadgeCheck, Bell, Copy, Factory, GitBranch, Network, Plus, RadioTower, ReceiptText, RefreshCw, ShieldCheck, Split, Users } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import type React from 'react';
import { FormEvent, useState } from 'react';
import { connectPeer, postAction } from './api';
import {
  ChannelRecord,
  FactoryRecord,
  Hex32,
  HubEvent,
  InvoiceRecord,
  NodeState,
  PeerRecord,
  Pubkey,
  RecordProvenance,
  WatchAlertSeverity,
  WatchtowerAlertRecord,
  assertHex32,
  assertPositiveInteger,
  assertRemotePubkey,
  assetLabel,
  formatAmount,
  formatBalance,
  formatTime,
  formatTimeMs,
  shortHex,
} from './domain';

type RunAction = (label: string, action: () => Promise<NodeState>) => Promise<void>;
type TimeFilter = 'all' | '1h' | '24h' | '7d';
type EventSeverityFilter = 'all' | HubEvent['severity'];
type WatchSeverityFilter = 'all' | WatchAlertSeverity;

const MAX_PEER_ALIAS_LEN = 80;
const SIDE_PANEL_PREVIEW_LIMIT = 5;
const EVENT_PREVIEW_LIMIT = 10;

export function ChannelTable({
  channels,
  totalCount,
  searchActive,
  runAction,
  busy,
  onOpenAction,
}: {
  channels: ChannelRecord[];
  totalCount: number;
  searchActive: boolean;
  runAction: RunAction;
  busy: boolean;
  onOpenAction: () => void;
}) {
  return (
    <section className="panel table-panel">
      <div className="section-head">
        <h2>Channels</h2>
        <span className="badge">{searchActive ? `${channels.length}/${totalCount} tracked` : `${channels.length} tracked`}</span>
      </div>
      <table>
        <thead>
          <tr>
            <th>Channel</th>
            <th>Phase</th>
            <th>State</th>
            <th>Funding</th>
            <th>Value</th>
            <th>Sponsor</th>
            <th>Source</th>
            <th>Next action</th>
          </tr>
        </thead>
        <tbody>
          {channels.length === 0 && (
            <tr>
              <td colSpan={8}>
                {searchActive ? (
                  <div className="empty">No channels match this filter</div>
                ) : (
                  <RichEmptyState
                    Icon={GitBranch}
                    title="No channels yet"
                    detail="Open a bilateral channel to start tracking local off-chain state."
                    actionLabel="Open channel"
                    onAction={onOpenAction}
                    disabled={busy}
                  />
                )}
              </td>
            </tr>
          )}
          {channels.map(channel => (
            <tr key={channel.channel_id}>
              <td>
                <span className="copy-line"><strong>{shortHex(channel.channel_id)}</strong><CopyButton value={channel.channel_id} label="Copy channel id" /></span>
                <span className="copy-line muted"><small>{shortHex(channel.counterparty_pubkey)}</small><CopyButton value={channel.counterparty_pubkey} label="Copy counterparty pubkey" /></span>
              </td>
              <td><span className={`phase ${channel.phase}`}>{channel.phase}</span></td>
              <td className="mono">#{channel.state_number}</td>
              <td>
                <strong>epoch {channel.funding_epoch}</strong>
                <span className="copy-line muted"><small>{shortHex(channel.funding_context_id)}</small><CopyButton value={channel.funding_context_id} label="Copy funding context id" /></span>
              </td>
              <td className="mono">{formatBalance(channel.balances[0])}</td>
              <td className="mono">{formatAmount(channel.sponsor_budget, { kind: 'ckb' })}</td>
              <td><ProvenanceBadge provenance={channel.provenance} /></td>
              <td>
                <ChannelRowActions channel={channel} runAction={runAction} busy={busy} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

function ChannelRowActions({
  channel,
  runAction,
  busy,
}: {
  channel: ChannelRecord;
  runAction: RunAction;
  busy: boolean;
}) {
  const [confirmingFinalise, setConfirmingFinalise] = useState(false);
  const canPublish = channel.phase === 'active' || channel.phase === 'settling';
  const canSplice = channel.phase === 'active';
  const canFinalise = channel.phase === 'settling';

  const publish = () => {
    void runAction('Update tracked state', () => postAction(`/api/channels/${channel.channel_id}/publish`, {
      funding_context_id: channel.funding_context_id,
      state_number: channel.state_number + 1,
    }));
  };

  const splice = () => {
    const nextFundingEpoch = channel.funding_epoch + 1;
    const nextFundingContextId = randomHex32();
    void runAction('Record splice', () => postAction(`/api/channels/${channel.channel_id}/splice`, {
      new_funding_epoch: nextFundingEpoch,
      new_funding_context_id: nextFundingContextId,
    }));
  };

  const finalise = () => {
    void runAction('Finalise channel', () => postAction(`/api/channels/${channel.channel_id}/finalise`)).then(() => setConfirmingFinalise(false));
  };

  if (!canPublish && !canSplice && !canFinalise) {
    return <span className="row-action-empty">No action</span>;
  }

  return (
    <div className="row-actions" aria-label={`Actions for channel ${channel.channel_id}`}>
      {canPublish && (
        <button
          type="button"
          className="row-action"
          data-testid="channel-row-publish"
          data-channel-id={channel.channel_id}
          onClick={publish}
          disabled={busy}
          title={`Update tracked state ${channel.state_number + 1} for ${shortHex(channel.channel_id)}`}
        >
          <RadioTower size={12} />
          Update state
        </button>
      )}
      {canSplice && (
        <button
          type="button"
          className="row-action"
          data-testid="channel-row-splice"
          data-channel-id={channel.channel_id}
          onClick={splice}
          disabled={busy}
          title={`Record ${shortHex(channel.channel_id)} splice to epoch ${channel.funding_epoch + 1}`}
        >
          <Split size={12} />
          Record splice
        </button>
      )}
      {canFinalise && (
        <button
          type="button"
          className="row-action primary"
          data-testid="channel-row-finalise"
          data-channel-id={channel.channel_id}
          onClick={() => setConfirmingFinalise(true)}
          disabled={busy}
          title={`Finalise ${shortHex(channel.channel_id)}`}
        >
          <BadgeCheck size={12} />
          Finalise
        </button>
      )}
      {confirmingFinalise && (
        <ConfirmActionDialog
          title={`Finalise channel ${shortHex(channel.channel_id)}?`}
          detail={`This closes the settling channel at state ${channel.state_number}. It cannot be undone from this console.`}
          confirmLabel="Finalise"
          confirmTestId="confirm-finalise"
          busy={busy}
          onCancel={() => setConfirmingFinalise(false)}
          onConfirm={finalise}
        />
      )}
    </div>
  );
}

function ConfirmActionDialog({
  title,
  detail,
  confirmLabel,
  confirmTestId = 'confirm-action',
  busy,
  onCancel,
  onConfirm,
}: {
  title: string;
  detail: string;
  confirmLabel: string;
  confirmTestId?: string;
  busy: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  return (
    <div className="modal-backdrop" role="presentation">
      <div className="confirm-dialog" role="dialog" aria-modal="true" aria-labelledby="confirm-dialog-title">
        <div>
          <h3 id="confirm-dialog-title">{title}</h3>
          <p>{detail}</p>
        </div>
        <div className="confirm-dialog-actions">
          <button type="button" className="copy-button" onClick={onCancel} disabled={busy}>Cancel</button>
          <button type="button" className="danger-button" data-testid={confirmTestId} onClick={onConfirm} disabled={busy}>
            <BadgeCheck size={15} /> {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

export function InvoicePanel({
  invoices,
  totalCount,
  searchActive,
  onOpenAction,
}: {
  invoices: InvoiceRecord[];
  totalCount: number;
  searchActive: boolean;
  onOpenAction: () => void;
}) {
  const [showAll, setShowAll] = useState(false);
  const orderedInvoices = sortInvoicesNewestFirst(invoices);
  const visibleInvoices = showAll ? orderedInvoices : orderedInvoices.slice(0, SIDE_PANEL_PREVIEW_LIMIT);
  const openCount = invoices.filter(invoice => invoice.status === 'open').length;
  return (
    <section className="panel">
      <div className="section-head">
        <h2>Invoices</h2>
        <span className="badge">{searchActive ? `${invoices.length}/${totalCount} shown` : `${openCount} open`}</span>
      </div>
      <div className="stack-list">
        {invoices.length === 0 && (searchActive ? (
          <div className="empty">No invoices match this filter</div>
        ) : (
          <RichEmptyState
            Icon={ReceiptText}
            title="No invoices yet"
            detail="Create or decode an invoice to track payment state in this Hub."
            actionLabel="Open invoices"
            onAction={onOpenAction}
          />
        ))}
        {visibleInvoices.map(invoice => (
            <div className="list-row evidence-row" key={invoice.invoice_id}>
              <div>
                <span className="copy-line"><strong>{invoice.description || shortHex(invoice.invoice_id)}</strong><CopyButton value={invoice.encoded_invoice} label="Copy encoded invoice" /></span>
                <span className="copy-line muted"><small>{formatAmount(invoice.amount, invoice.asset)} · {assetLabel(invoice.asset)} · {shortHex(invoice.payment_hash)}</small><CopyButton value={invoice.payment_hash} label="Copy payment hash" /></span>
                <small>expires {formatTime(invoice.expires_at_unix)}</small>
              </div>
              <div className="row-badges">
                <span className={`status ${invoice.status}`}>{invoice.status}</span>
                <ProvenanceBadge provenance={invoice.provenance} />
              </div>
              <InvoiceEvidenceInspector invoice={invoice} />
            </div>
          ))}
      </div>
      <ListToggle
        label="invoices"
        totalCount={orderedInvoices.length}
        visibleCount={visibleInvoices.length}
        showAll={showAll}
        onToggle={() => setShowAll(value => !value)}
      />
    </section>
  );
}

function InvoiceEvidenceInspector({ invoice }: { invoice: InvoiceRecord }) {
  const channelId = invoice.channel_id ?? null;
  const paidOrCancelledAt = invoice.paid_at_unix ?? invoice.cancelled_at_unix ?? null;
  const paidOrCancelledLabel = invoice.paid_at_unix
    ? 'Paid'
    : invoice.cancelled_at_unix
      ? 'Cancelled'
      : 'Paid/cancelled';
  return (
    <div className="evidence-inspector invoice-evidence" data-testid="invoice-evidence-inspector">
      <EvidenceField label="Created" value={formatTime(invoice.created_at_unix)} />
      <EvidenceField label="Received" value={invoice.received_at_unix ? formatTime(invoice.received_at_unix) : undefined} />
      <EvidenceField label={paidOrCancelledLabel} value={paidOrCancelledAt ? formatTime(paidOrCancelledAt) : undefined} />
      <EvidenceField label="Payee node" value={shortHex(invoice.payee_node_id)} copyValue={invoice.payee_node_id} mono />
      <EvidenceField label="Channel" value={channelId ? shortHex(channelId) : undefined} copyValue={channelId} mono />
      <EvidenceField label="Payment hash" value={shortHex(invoice.payment_hash)} copyValue={invoice.payment_hash} mono />
    </div>
  );
}

export function PeerPanel({
  state,
  peers,
  totalCount,
  searchActive,
  runAction,
  busy,
  onOpenAction,
}: {
  state: NodeState;
  peers: PeerRecord[];
  totalCount: number;
  searchActive: boolean;
  runAction: RunAction;
  busy: boolean;
  onOpenAction: () => void;
}) {
  const [quickAddOpen, setQuickAddOpen] = useState(false);
  const [showAll, setShowAll] = useState(false);
  const [pubkey, setPubkey] = useState('');
  const [alias, setAlias] = useState('');
  const visiblePeers = showAll ? peers : peers.slice(0, SIDE_PANEL_PREVIEW_LIMIT);

  const submitQuickAdd = (event: FormEvent) => {
    event.preventDefault();
    void runAction('Connect peer', () => connectPeer(assertRemotePubkey(pubkey, state.pubkey, 'Peer pubkey'), requiredText(alias, 'Alias'))).then(() => {
      setPubkey('');
      setAlias('');
      setQuickAddOpen(false);
    });
  };

  return (
    <section className="panel">
      <div className="section-head">
        <h2>Peers</h2>
        <div className="section-actions">
          <span className="badge">{searchActive ? `${peers.length}/${totalCount} connected` : `${peers.length} connected`}</span>
          <button type="button" className="row-action primary" data-testid="peer-panel-add" onClick={() => setQuickAddOpen(open => !open)} disabled={busy}>
            <Plus size={12} /> Add
          </button>
        </div>
      </div>
      {quickAddOpen && (
        <form className="quick-row-form" onSubmit={submitQuickAdd}>
          <ValidatedInput label="Peer pubkey" className="mono" testId="peer-panel-pubkey" value={pubkey} onChange={setPubkey} validate={value => { assertRemotePubkey(value, state.pubkey, 'Peer pubkey'); }} />
          <ValidatedInput label="Alias" testId="peer-panel-alias" value={alias} onChange={setAlias} maxLength={MAX_PEER_ALIAS_LEN} validate={value => { requiredText(value, 'Alias'); }} />
          <button data-testid="peer-panel-connect" disabled={busy}><Users size={15} /> Connect</button>
        </form>
      )}
      <div className="stack-list">
        {peers.length === 0 && (searchActive ? (
          <div className="empty">No peers match this filter</div>
        ) : (
          <RichEmptyState
            Icon={Users}
            title="No peers connected"
            detail="Add a counterparty pubkey before opening channels or factories."
            actionLabel="Open peer controls"
            onAction={onOpenAction}
            disabled={busy}
          />
        ))}
        {visiblePeers.map(peer => (
          <div className="list-row" key={peer.node_id}>
            <div>
              <strong>{peer.alias}</strong>
              <span className="copy-line muted"><small>{shortHex(peer.pubkey)}</small><CopyButton value={peer.pubkey} label="Copy peer pubkey" /></span>
              <span className="copy-line muted"><small>node {shortHex(peer.node_id)}</small><CopyButton value={peer.node_id} label="Copy peer node id" /></span>
            </div>
            <ProvenanceBadge provenance={peer.provenance} />
          </div>
        ))}
      </div>
      <ListToggle
        label="peers"
        totalCount={peers.length}
        visibleCount={visiblePeers.length}
        showAll={showAll}
        onToggle={() => setShowAll(value => !value)}
      />
    </section>
  );
}

export function FactoryPanel({
  factories,
  totalCount,
  searchActive,
  runAction,
  busy,
  onOpenAction,
  onMaterialise,
}: {
  factories: FactoryRecord[];
  totalCount: number;
  searchActive: boolean;
  runAction: RunAction;
  busy: boolean;
  onOpenAction: () => void;
  onMaterialise: (factoryId: Hex32) => void;
}) {
  return (
    <section className="panel">
      <div className="section-head">
        <h2>Factories</h2>
        <span className="badge">{searchActive ? `${factories.length}/${totalCount} active` : `${factories.length} active`}</span>
      </div>
      <div className="stack-list">
        {factories.length === 0 && (searchActive ? (
          <div className="empty">No factories match this filter</div>
        ) : (
          <RichEmptyState
            Icon={Factory}
            title="No factories yet"
            detail="Open a factory to track shared reserve state and materialise child channels."
            actionLabel="Open factory"
            onAction={onOpenAction}
            disabled={busy}
          />
        ))}
        {factories.map(factory => (
          <div className="list-row evidence-row" key={factory.factory_id}>
            <div>
              <span className="copy-line"><strong>{shortHex(factory.factory_id)}</strong><CopyButton value={factory.factory_id} label="Copy factory id" /></span>
              <small>update {factory.update_number} · {factory.materialised_child_channels.length} children</small>
            </div>
            <div className="row-badges">
              <span className="amount">{formatBalance(factory.reserve_balances[0])}</span>
              <ProvenanceBadge provenance={factory.provenance} />
              <FactoryRowActions factory={factory} runAction={runAction} busy={busy} onMaterialise={onMaterialise} />
            </div>
            <FactoryEvidenceInspector factory={factory} />
          </div>
        ))}
      </div>
    </section>
  );
}

function FactoryEvidenceInspector({ factory }: { factory: FactoryRecord }) {
  const firstChild = factory.materialised_child_channels[0] ?? null;
  const participantPreview = factory.participant_node_ids.slice(0, 2);
  const reserve = factory.reserve_balances[0];
  return (
    <div className="evidence-inspector factory-evidence" data-testid="factory-evidence-inspector">
      <EvidenceField label="Proof scope" value="local factory record" />
      <EvidenceField label="Update" value={`#${factory.update_number}`} mono />
      <EvidenceField label="Participants" value={`${factory.participant_node_ids.length} nodes`} />
      <EvidenceField label="Reserve" value={reserve ? formatBalance(reserve) : undefined} mono />
      <EvidenceField label="First child" value={firstChild ? shortHex(firstChild) : undefined} copyValue={firstChild} mono />
      <div className="evidence-field wide">
        <span>Participant ids</span>
        <div className="evidence-chips">
          {participantPreview.map(nodeId => (
            <span className="mono copy-line" key={nodeId}>
              {shortHex(nodeId)}
              <CopyButton value={nodeId} label="Copy participant node id" />
            </span>
          ))}
          {factory.participant_node_ids.length > participantPreview.length && (
            <span>{factory.participant_node_ids.length - participantPreview.length} more</span>
          )}
        </div>
      </div>
    </div>
  );
}

function FactoryRowActions({
  factory,
  runAction,
  busy,
  onMaterialise,
}: {
  factory: FactoryRecord;
  runAction: RunAction;
  busy: boolean;
  onMaterialise: (factoryId: Hex32) => void;
}) {
  const advance = () => {
    void runAction('Advance factory', () => postAction(`/api/factories/${factory.factory_id}/advance`, {
      new_update_number: factory.update_number + 1,
    }));
  };

  return (
    <div className="row-actions" aria-label={`Actions for factory ${factory.factory_id}`}>
      <button
        type="button"
        className="row-action"
        data-testid="factory-row-advance"
        data-factory-id={factory.factory_id}
        onClick={advance}
        disabled={busy}
        title={`Advance ${shortHex(factory.factory_id)} to update ${factory.update_number + 1}`}
      >
        <RefreshCw size={12} />
        Advance
      </button>
      <button
        type="button"
        className="row-action primary"
        data-testid="factory-row-materialise"
        data-factory-id={factory.factory_id}
        onClick={() => onMaterialise(factory.factory_id)}
        disabled={busy}
        title={`Materialise child from ${shortHex(factory.factory_id)}`}
      >
        <Network size={12} />
        Child
      </button>
    </div>
  );
}

export function WatchtowerPanel({
  watchtower,
  alerts,
  totalCount,
  searchActive,
  onOpenAction,
}: {
  watchtower: NodeState['watchtower'];
  alerts: WatchtowerAlertRecord[];
  totalCount: number;
  searchActive: boolean;
  onOpenAction: () => void;
}) {
  const [severityFilter, setSeverityFilter] = useState<WatchSeverityFilter>('all');
  const [timeFilter, setTimeFilter] = useState<TimeFilter>('all');
  const [showAll, setShowAll] = useState(false);
  const filteredAlerts = sortWatchtowerAlertsNewestFirst(alerts.filter(alert => (
    (severityFilter === 'all' || alert.severity === severityFilter)
    && withinTimeWindow(alert.created_unix_ms, timeFilter)
  )));
  const filterActive = severityFilter !== 'all' || timeFilter !== 'all';
  const badge = !watchtower.configured
    ? 'not configured'
    : searchActive || filterActive
      ? `${filteredAlerts.length}/${searchActive ? totalCount : alerts.length} alerts`
      : `${totalCount} alerts`;
  const visibleAlerts = showAll ? filteredAlerts : filteredAlerts.slice(0, EVENT_PREVIEW_LIMIT);
  return (
    <section className="panel watchtower-panel">
      <div className="section-head">
        <h2>Watchtower</h2>
        <span className={`badge ${watchtower.last_error ? 'remaining' : alerts.length ? 'remaining' : ''}`}>{badge}</span>
      </div>
      {watchtower.alert_file && (
        <div className="watchtower-source">
          <RadioTower size={14} />
          <span className="mono">{watchtower.alert_file}</span>
          <ProvenanceBadge provenance={watchtower.provenance} />
        </div>
      )}
      {watchtower.last_error && <small className="inline-error watchtower-error">{watchtower.last_error}</small>}
      {watchtower.configured && (
        <WatchtowerOperationalView
          alerts={alerts}
          latestAlert={filteredAlerts[0] ?? alerts[0]}
          fileExists={watchtower.file_exists}
        />
      )}
      {watchtower.configured && watchtower.file_exists && (
        <div className="filter-row">
          <label>
            Severity
            <select value={severityFilter} onChange={event => setSeverityFilter(event.target.value as WatchSeverityFilter)}>
              <option value="all">all</option>
              <option value="warning">warning</option>
              <option value="info">info</option>
            </select>
          </label>
          <label>
            Time
            <select value={timeFilter} onChange={event => setTimeFilter(event.target.value as TimeFilter)}>
              <option value="all">all</option>
              <option value="1h">last hour</option>
              <option value="24h">last day</option>
              <option value="7d">last 7 days</option>
            </select>
          </label>
        </div>
      )}
      {!watchtower.configured && (
        <RichEmptyState
          Icon={RadioTower}
          title="No watchtower alert file configured"
          detail="Restart Hub with a watchtower alert JSONL path to surface recovery evidence here."
          actionLabel="Open state file controls"
          onAction={onOpenAction}
        />
      )}
      {watchtower.configured && !watchtower.file_exists && (
        <RichEmptyState
          Icon={RadioTower}
          title="Watchtower alert file pending"
          detail="The configured alert file has not been written yet; keep the watchtower service running and refresh after the first scan."
          actionLabel="Open state file controls"
          onAction={onOpenAction}
        />
      )}
      {watchtower.configured && watchtower.file_exists && filteredAlerts.length === 0 && (
        searchActive ? (
          <div className="empty">No watchtower alerts match this filter</div>
        ) : filterActive ? (
          <div className="empty">No watchtower alerts match the selected severity or time window</div>
        ) : (
          <RichEmptyState
            Icon={ShieldCheck}
            title="No watchtower alerts recorded"
            detail="The feed is attached, but no publication or recovery alert has been observed."
            actionLabel="Open state file controls"
            onAction={onOpenAction}
          />
        )
      )}
      {filteredAlerts.length > 0 && (
        <div className="event-log watchtower-log">
          {visibleAlerts.map(alert => (
            <div className={`event-entry ${alert.severity}`} key={`${alert.created_unix_ms}-${alert.channel_id}-${alert.event}`}>
              <EventMark severity={alert.severity === 'warning' ? 'warning' : 'info'} />
              <div className="event-main">
                <div className="event-line">
                  <strong>{alert.event}</strong>
                  <time dateTime={new Date(alert.created_unix_ms).toISOString()}>{formatTimeMs(alert.created_unix_ms)}</time>
                </div>
                <small>{alert.message}</small>
                <div className="event-meta">
                  <span className="mono copy-line">{shortHex(alert.channel_id)}<CopyButton value={alert.channel_id} label="Copy alert channel id" /></span>
                  <span className="mono">selected #{alert.selected_state_number}</span>
                  {alert.observed_state_number != null && <span className="mono">observed #{alert.observed_state_number}</span>}
                  <span className="mono">scan {alert.scanned_to_block}</span>
                  {alert.publication_tx_hash && <span className="mono copy-line">tx {shortHex(alert.publication_tx_hash)}<CopyButton value={alert.publication_tx_hash} label="Copy publication tx hash" /></span>}
                  <ProvenanceBadge provenance={alert.provenance} />
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
      <ListToggle
        label="alerts"
        totalCount={filteredAlerts.length}
        visibleCount={visibleAlerts.length}
        showAll={showAll}
        onToggle={() => setShowAll(value => !value)}
      />
    </section>
  );
}

function WatchtowerOperationalView({
  alerts,
  latestAlert,
  fileExists,
}: {
  alerts: WatchtowerAlertRecord[];
  latestAlert?: WatchtowerAlertRecord;
  fileExists: boolean;
}) {
  const scannedToBlock = alerts.reduce((max, alert) => Math.max(max, alert.scanned_to_block), 0);
  const nextFromBlock = latestAlert?.next_from_block;
  const publications = alerts.filter(alert => alert.publication_tx_hash).length;
  const lastEvent = latestAlert ? latestAlert.event.replace(/_/g, ' ') : 'none';
  return (
    <div className="watchtower-operational" data-testid="watchtower-operational-view">
      <div className="watchtower-summary-grid">
        <article>
          <span>Scan policy</span>
          <strong>{fileExists ? `next from ${nextFromBlock ?? 0}` : 'waiting for file'}</strong>
          <small>{fileExists ? `scanned to block ${scannedToBlock}` : 'the configured alert source has not emitted evidence yet'}</small>
        </article>
        <article>
          <span>Last alert</span>
          <strong>{lastEvent}</strong>
          <small>{latestAlert ? formatTimeMs(latestAlert.created_unix_ms) : 'no alert observed'}</small>
        </article>
        <article>
          <span>Selected state</span>
          <strong>{latestAlert ? `#${latestAlert.selected_state_number}` : 'not available'}</strong>
          <small>{latestAlert?.observed_state_number != null ? `observed #${latestAlert.observed_state_number}` : 'no competing observed state'}</small>
        </article>
        <article>
          <span>Publication txs</span>
          <strong>{publications}</strong>
          <small>{latestAlert?.publication_tx_hash ? shortHex(latestAlert.publication_tx_hash) : 'none submitted from this feed'}</small>
        </article>
      </div>
      {latestAlert && <WatchtowerAlertInspector alert={latestAlert} />}
    </div>
  );
}

function WatchtowerAlertInspector({ alert }: { alert: WatchtowerAlertRecord }) {
  return (
    <div className="evidence-inspector watchtower-evidence" data-testid="watchtower-alert-inspector">
      <EvidenceField label="Channel" value={shortHex(alert.channel_id)} copyValue={alert.channel_id} mono />
      <EvidenceField label="Out-point" value={alert.observed_out_point} copyValue={alert.observed_out_point} mono />
      <EvidenceField label="Publication tx" value={alert.publication_tx_hash ? shortHex(alert.publication_tx_hash) : undefined} copyValue={alert.publication_tx_hash} mono />
      <EvidenceField label="Selected anchor" value={alert.selected_funding_anchor ? shortHex(alert.selected_funding_anchor) : undefined} copyValue={alert.selected_funding_anchor} mono />
      <EvidenceField label="Observed anchor" value={alert.observed_funding_anchor ? shortHex(alert.observed_funding_anchor) : undefined} copyValue={alert.observed_funding_anchor} mono />
      <EvidenceField label="Selected context" value={alert.selected_funding_context_id ? shortHex(alert.selected_funding_context_id) : undefined} copyValue={alert.selected_funding_context_id} mono />
    </div>
  );
}

export function EventPanel({
  events,
  totalCount,
  searchActive,
  onRefresh,
  busy,
}: {
  events: HubEvent[];
  totalCount: number;
  searchActive: boolean;
  onRefresh: () => void;
  busy: boolean;
}) {
  const [severityFilter, setSeverityFilter] = useState<EventSeverityFilter>('all');
  const [timeFilter, setTimeFilter] = useState<TimeFilter>('all');
  const [showAll, setShowAll] = useState(false);
  const filteredEvents = events.filter(event => (
    (severityFilter === 'all' || event.severity === severityFilter)
    && withinTimeWindow(event.created_at_unix * 1000, timeFilter)
  ));
  const filterActive = severityFilter !== 'all' || timeFilter !== 'all';
  const visibleEvents = showAll ? filteredEvents : filteredEvents.slice(0, EVENT_PREVIEW_LIMIT);
  return (
    <section className="panel">
      <div className="section-head">
        <h2>Events</h2>
        <span className="badge">{searchActive || filterActive ? `${filteredEvents.length}/${searchActive ? totalCount : events.length} recorded` : `${events.length} recorded`}</span>
      </div>
      <div className="filter-row">
        <label>
          Severity
          <select value={severityFilter} onChange={event => setSeverityFilter(event.target.value as EventSeverityFilter)}>
            <option value="all">all</option>
            <option value="critical">critical</option>
            <option value="warning">warning</option>
            <option value="info">info</option>
          </select>
        </label>
        <label>
          Time
          <select value={timeFilter} onChange={event => setTimeFilter(event.target.value as TimeFilter)}>
            <option value="all">all</option>
            <option value="1h">last hour</option>
            <option value="24h">last day</option>
            <option value="7d">last 7 days</option>
          </select>
        </label>
      </div>
      <div className="event-log">
        {filteredEvents.length === 0 && (searchActive ? (
          <div className="empty">No events match this filter</div>
        ) : filterActive ? (
          <div className="empty">No events match the selected severity or time window</div>
        ) : (
          <RichEmptyState
            Icon={Bell}
            title="No API events recorded"
            detail="Events appear after local mutations, watchtower imports, or explicit refreshes from the Hub API."
            actionLabel="Refresh now"
            onAction={onRefresh}
            disabled={busy}
          />
        ))}
        {visibleEvents.map(event => (
          <div className={`event-entry ${event.severity}`} key={event.id}>
            <EventMark severity={event.severity} />
            <div className="event-main">
              <div className="event-line">
                <strong>{event.event}</strong>
                <time dateTime={new Date(event.created_at_unix * 1000).toISOString()}>{formatTime(event.created_at_unix)}</time>
              </div>
              <small>{event.message}</small>
              <div className="event-meta">
                {event.subject_id && <span className="mono copy-line">{shortHex(event.subject_id)}<CopyButton value={event.subject_id} label="Copy event subject id" /></span>}
                <ProvenanceBadge provenance={event.provenance} />
              </div>
            </div>
          </div>
        ))}
      </div>
      <ListToggle
        label="events"
        totalCount={filteredEvents.length}
        visibleCount={visibleEvents.length}
        showAll={showAll}
        onToggle={() => setShowAll(value => !value)}
      />
    </section>
  );
}

function ListToggle({
  label,
  totalCount,
  visibleCount,
  showAll,
  onToggle,
}: {
  label: string;
  totalCount: number;
  visibleCount: number;
  showAll: boolean;
  onToggle: () => void;
}) {
  if (totalCount <= visibleCount && !showAll) return null;
  return (
    <div className="list-toggle-row">
      <button type="button" className="copy-button" onClick={onToggle}>
        {showAll ? `Show fewer ${label}` : `Show all ${totalCount} ${label}`}
      </button>
      {!showAll && visibleCount < totalCount && <small>{totalCount - visibleCount} hidden</small>}
    </div>
  );
}

function EventMark({ severity }: { severity: HubEvent['severity'] }) {
  const Icon = severity === 'info' ? Activity : AlertTriangle;
  return (
    <span className={`event-mark ${severity}`}>
      <Icon size={14} />
    </span>
  );
}
function ProvenanceBadge({ provenance }: { provenance: RecordProvenance }) {
  return (
    <span className={'provenance-badge ' + provenance.chain_status} title={provenance.message}>
      {provenance.label}
    </span>
  );
}

function RichEmptyState({
  Icon,
  title,
  detail,
  actionLabel,
  onAction,
  disabled,
}: {
  Icon: LucideIcon;
  title: string;
  detail: string;
  actionLabel?: string;
  onAction?: () => void;
  disabled?: boolean;
}) {
  return (
    <div className="empty rich">
      <Icon size={24} />
      <strong>{title}</strong>
      <small>{detail}</small>
      {actionLabel && onAction && (
        <button type="button" className="row-action primary" onClick={onAction} disabled={disabled}>
          <Plus size={12} /> {actionLabel}
        </button>
      )}
    </div>
  );
}

function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  const [failed, setFailed] = useState(false);

  const copyValue = async () => {
    setFailed(false);
    try {
      await copyTextToClipboard(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1_500);
    } catch {
      setFailed(true);
      window.setTimeout(() => setFailed(false), 2_500);
    }
  };

  return (
    <button
      type="button"
      className={'copy-icon ' + (copied ? 'copied' : '') + ' ' + (failed ? 'failed' : '')}
      title={failed ? 'Copy failed' : copied ? 'Copied' : label}
      aria-label={failed ? 'Copy failed' : copied ? 'Copied' : label}
      onClick={copyValue}
    >
      {copied ? <BadgeCheck size={12} /> : <Copy size={12} />}
    </button>
  );
}

function EvidenceField({
  label,
  value,
  copyValue,
  mono = false,
}: {
  label: string;
  value?: React.ReactNode;
  copyValue?: string | null;
  mono?: boolean;
}) {
  const empty = value == null || value === '';
  return (
    <div className="evidence-field">
      <span>{label}</span>
      <strong className={mono ? 'mono copy-line' : ''}>
        {empty ? 'not available' : value}
        {copyValue && <CopyButton value={copyValue} label={'Copy ' + label.toLowerCase()} />}
      </strong>
    </div>
  );
}

function ValidatedInput({
  label,
  value,
  onChange,
  validate,
  testId,
  className,
  maxLength,
  disabled,
}: {
  label: React.ReactNode;
  value: string;
  onChange: (value: string) => void;
  validate: (value: string) => void;
  testId?: string;
  className?: string;
  maxLength?: number;
  disabled?: boolean;
}) {
  const [touched, setTouched] = useState(false);
  const error = touched ? validationError(value, validate) : '';
  return (
    <label>
      {label}
      <input
        className={((className ?? '') + ' ' + (error ? 'invalid' : '')).trim()}
        data-testid={testId}
        value={value}
        maxLength={maxLength}
        disabled={disabled}
        onBlur={() => setTouched(true)}
        onChange={event => onChange(event.target.value)}
      />
      {error && <small className="field-error">{error}</small>}
    </label>
  );
}

function validationError(value: string, validate: (value: string) => void): string {
  try {
    validate(value);
    return '';
  } catch (err) {
    return String((err as Error).message);
  }
}

function requiredText(value: string, label: string): string {
  const trimmed = value.trim();
  if (!trimmed) throw new Error(label + ' is required.');
  return trimmed;
}

function randomHex32(): Hex32 {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return ('0x' + Array.from(bytes).map(byte => byte.toString(16).padStart(2, '0')).join('')) as Hex32;
}

function sortInvoicesNewestFirst(invoices: InvoiceRecord[]): InvoiceRecord[] {
  return [...invoices].sort((left, right) => {
    const byCreated = right.created_at_unix - left.created_at_unix;
    return byCreated || left.invoice_id.localeCompare(right.invoice_id);
  });
}

function sortWatchtowerAlertsNewestFirst(alerts: WatchtowerAlertRecord[]): WatchtowerAlertRecord[] {
  return [...alerts].sort((left, right) => {
    const byCreated = right.created_unix_ms - left.created_unix_ms;
    return byCreated || left.channel_id.localeCompare(right.channel_id);
  });
}

function withinTimeWindow(timestampMs: number, filter: TimeFilter): boolean {
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

async function copyTextToClipboard(text: string): Promise<void> {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.setAttribute('readonly', 'true');
  textarea.style.position = 'fixed';
  textarea.style.opacity = '0';
  document.body.appendChild(textarea);
  textarea.select();
  const ok = document.execCommand('copy');
  document.body.removeChild(textarea);
  if (!ok) throw new Error('clipboard copy failed');
}
