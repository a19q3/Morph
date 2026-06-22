import {
  Activity,
  AlertTriangle,
  BadgeCheck,
  Blocks,
  CheckCircle2,
  Copy,
  Database,
  Factory,
  FileJson,
  GitBranch,
  Landmark,
  Network,
  Plus,
  RadioTower,
  ReceiptText,
  RefreshCw,
  ShieldCheck,
  Split,
  Upload,
  WalletCards,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import type React from 'react';
import { FormEvent, useCallback, useEffect, useMemo, useState } from 'react';
import { getState, getStateFile, postAction, replaceStateFile } from './api';
import {
  Asset,
  Balance,
  ChannelRecord,
  FactoryRecord,
  FlowKey,
  Hex32,
  HubEvent,
  InvoiceRecord,
  NodeState,
  PeerRecord,
  assertHex32,
  assertNonNegativeInteger,
  assertPositiveInteger,
  emptyState,
  formatAmount,
  formatBalance,
  shortHex,
} from './domain';

type ActionPanel = 'invoice' | 'channel' | 'factory' | 'state';
type RunAction = (label: string, action: () => Promise<NodeState>) => Promise<void>;

const actionItems: { key: ActionPanel; label: string; Icon: LucideIcon }[] = [
  { key: 'invoice', label: 'Invoices', Icon: ReceiptText },
  { key: 'channel', label: 'Channels', Icon: GitBranch },
  { key: 'factory', label: 'Factories', Icon: Factory },
  { key: 'state', label: 'State file', Icon: FileJson },
];

const flowLabels: Record<FlowKey, string> = {
  peer: 'Peer',
  'invoice-created': 'Invoice created',
  'invoice-received': 'Invoice received',
  'invoice-settled': 'Invoice settled',
  'channel-opened': 'Channel opened',
  'state-published': 'State published',
  'channel-finalised': 'Channel finalised',
  'channel-spliced': 'Channel spliced',
  'factory-opened': 'Factory opened',
  'factory-advanced': 'Factory advanced',
  'factory-child': 'Factory child',
};

export function App() {
  const [state, setState] = useState<NodeState>(emptyState);
  const [activeAction, setActiveAction] = useState<ActionPanel>('invoice');
  const [status, setStatus] = useState('Loading Morph Hub API');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    const next = await getState();
    setState(next);
    setError('');
    setStatus('State refreshed from Morph Hub API');
    return next;
  }, []);

  useEffect(() => {
    refresh().catch(err => {
      setError(String((err as Error).message));
      setStatus('Morph Hub API is not reachable');
    });
  }, [refresh]);

  const runAction: RunAction = async (label, action) => {
    setBusy(true);
    setError('');
    setStatus(`${label} submitted`);
    try {
      const next = await action();
      setState(next);
      setStatus(`${label} accepted by Morph Hub API`);
    } catch (err) {
      setError(String((err as Error).message));
      setStatus(`${label} rejected`);
    } finally {
      setBusy(false);
    }
  };

  const totals = useMemo(() => {
    const vaultValue = state.channels.reduce((sum, channel) => sum + balanceTotal(channel.balances[0]), 0n);
    const sponsorBudget = state.channels.reduce((sum, channel) => sum + BigInt(channel.sponsor_budget), 0n);
    const settlingStates = state.channels.filter(channel => channel.phase === 'settling').length;
    const factoryReserve = state.factories.reduce(
      (sum, factory) => sum + factory.reserve_balances.reduce((inner, balance) => inner + balanceTotal(balance), 0n),
      0n
    );
    return { vaultValue, sponsorBudget, settlingStates, factoryReserve };
  }, [state.channels, state.factories]);

  const completedCount = state.completed_flows.length;
  const requiredCount = Math.max(state.required_flows.length, 1);
  const flowCoverage = Math.round((completedCount / requiredCount) * 100);

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">M</div>
          <div>
            <strong>Morph Hub</strong>
            <span>Operator console</span>
          </div>
        </div>
        <div className="node-card">
          <span>Node</span>
          <strong>{shortHex(state.node_id)}</strong>
          <small>{state.network}</small>
        </div>
        <div className="node-card">
          <span>State file</span>
          <strong>{state.state_path ? state.state_path.split('/').pop() : 'not loaded'}</strong>
          <small>{state.state_path}</small>
        </div>
        <div className="coverage">
          <div className="coverage-top">
            <span>Business flows</span>
            <strong>{completedCount}/{state.required_flows.length}</strong>
          </div>
          <div className="meter">
            <span style={{ width: `${flowCoverage}%` }} />
          </div>
          <small>{state.missing_flows.length === 0 ? 'All required flows recorded' : `${state.missing_flows.length} flows remaining`}</small>
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <h1>Morph Node</h1>
            <p>{status}</p>
          </div>
          <div className="topbar-status">
            <StatusPill tone={rpcTone(state.rpc.status)} icon={<ShieldCheck size={15} />} label={rpcLabel(state)} />
            <StatusPill tone="neutral" icon={<Blocks size={15} />} label={state.rpc.tip_height == null ? 'tip unavailable' : `tip ${state.rpc.tip_height}`} />
            <button className="icon-button" title="Refresh from API" onClick={() => runAction('Refresh', refresh)} disabled={busy}>
              <RefreshCw size={16} />
            </button>
          </div>
        </header>

        {error && <div className="error banner">{error}</div>}

        <section className="metric-grid">
          <Metric label="Vault value" value={formatAmount(totals.vaultValue, { kind: 'ckb' })} icon={<Landmark />} />
          <Metric label="Sponsor budget" value={formatAmount(totals.sponsorBudget, { kind: 'ckb' })} icon={<WalletCards />} />
          <Metric label="Settling states" value={String(totals.settlingStates)} icon={<AlertTriangle />} tone={totals.settlingStates ? 'warn' : 'base'} />
          <Metric label="Factory reserve" value={formatAmount(totals.factoryReserve, { kind: 'ckb' })} icon={<Factory />} />
        </section>

        <FlowPanel state={state} />

        <section className="content-grid">
          <ChannelTable channels={state.channels} />
          <InvoicePanel invoices={state.invoices} />
          <PeerPanel peers={state.peers} />
          <FactoryPanel factories={state.factories} />
          <EventPanel events={state.events} />
        </section>
      </section>

      <aside className="action-drawer">
        <div className="drawer-tabs">
          {actionItems.map(({ key, label, Icon }) => (
            <button
              className={activeAction === key ? 'selected' : ''}
              key={key}
              onClick={() => setActiveAction(key)}
              title={label}
              disabled={busy}
            >
              <Icon size={16} />
            </button>
          ))}
        </div>
        {activeAction === 'invoice' && <InvoiceActions state={state} runAction={runAction} busy={busy} />}
        {activeAction === 'channel' && <ChannelActions state={state} runAction={runAction} busy={busy} />}
        {activeAction === 'factory' && <FactoryActions state={state} runAction={runAction} busy={busy} />}
        {activeAction === 'state' && <StateActions state={state} runAction={runAction} busy={busy} />}
      </aside>
    </main>
  );
}

function StatusPill({
  icon,
  label,
  tone,
}: {
  icon: React.ReactNode;
  label: string;
  tone: 'good' | 'neutral' | 'warn' | 'bad';
}) {
  return <span className={`status-pill ${tone}`}>{icon}{label}</span>;
}

function Metric({ label, value, icon, tone = 'base' }: { label: string; value: string; icon: React.ReactNode; tone?: 'base' | 'warn' }) {
  return (
    <article className={`metric ${tone}`}>
      <div>{icon}</div>
      <span>{label}</span>
      <strong>{value}</strong>
    </article>
  );
}

function FlowPanel({ state }: { state: NodeState }) {
  const flows = state.required_flows.length ? state.required_flows : Object.keys(flowLabels) as FlowKey[];
  return (
    <section className="flow-panel">
      <div className="section-head">
        <h2>Business Flow</h2>
        <span>{state.missing_flows.length === 0 ? 'complete' : `${state.missing_flows.length} remaining`}</span>
      </div>
      <div className="flow-grid">
        {flows.map(flow => {
          const done = state.completed_flows.includes(flow);
          return (
            <div className={`flow-step ${done ? 'done' : ''}`} key={flow}>
              <span>{done ? <CheckCircle2 size={14} /> : <Activity size={14} />}</span>
              <strong>{flowLabels[flow]}</strong>
            </div>
          );
        })}
      </div>
    </section>
  );
}

function ChannelTable({ channels }: { channels: ChannelRecord[] }) {
  return (
    <section className="panel table-panel">
      <div className="section-head">
        <h2>Channels</h2>
        <span>{channels.length} tracked</span>
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
          </tr>
        </thead>
        <tbody>
          {channels.length === 0 && (
            <tr><td colSpan={6} className="empty">No channels in the hub state file</td></tr>
          )}
          {channels.map(channel => (
            <tr key={channel.channel_id}>
              <td><strong>{shortHex(channel.channel_id)}</strong><small>{shortHex(channel.counterparty_node_id)}</small></td>
              <td><span className={`phase ${channel.phase}`}>{channel.phase}</span></td>
              <td>{channel.state_number}</td>
              <td><strong>{channel.funding_epoch}</strong><small>{shortHex(channel.funding_context_id)}</small></td>
              <td>{formatBalance(channel.balances[0])}</td>
              <td>{formatAmount(channel.sponsor_budget, { kind: 'ckb' })}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

function InvoicePanel({ invoices }: { invoices: InvoiceRecord[] }) {
  return (
    <section className="panel">
      <div className="section-head">
        <h2>Invoices</h2>
        <span>{invoices.filter(invoice => invoice.status === 'open').length} open</span>
      </div>
      <div className="stack-list">
        {invoices.length === 0 && <div className="empty">No invoices in the hub state file</div>}
        {invoices.slice(0, 5).map(invoice => (
          <div className="list-row" key={invoice.invoice_id}>
            <div>
              <strong>{invoice.description || shortHex(invoice.invoice_id)}</strong>
              <small>{formatAmount(invoice.amount, invoice.asset)} · {shortHex(invoice.payment_hash)}</small>
            </div>
            <span className={`status ${invoice.status}`}>{invoice.status}</span>
          </div>
        ))}
      </div>
    </section>
  );
}

function PeerPanel({ peers }: { peers: PeerRecord[] }) {
  return (
    <section className="panel">
      <div className="section-head">
        <h2>Peers</h2>
        <span>{peers.length} connected</span>
      </div>
      <div className="stack-list">
        {peers.length === 0 && <div className="empty">No peers in the hub state file</div>}
        {peers.slice(0, 5).map(peer => (
          <div className="list-row" key={peer.node_id}>
            <div>
              <strong>{peer.alias}</strong>
              <small>{shortHex(peer.node_id)}</small>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

function FactoryPanel({ factories }: { factories: FactoryRecord[] }) {
  return (
    <section className="panel">
      <div className="section-head">
        <h2>Factories</h2>
        <span>{factories.length} active</span>
      </div>
      <div className="stack-list">
        {factories.length === 0 && <div className="empty">No factories in the hub state file</div>}
        {factories.map(factory => (
          <div className="list-row" key={factory.factory_id}>
            <div>
              <strong>{shortHex(factory.factory_id)}</strong>
              <small>update {factory.update_number} · {factory.materialised_child_channels.length} children</small>
            </div>
            <span className="amount">{formatBalance(factory.reserve_balances[0])}</span>
          </div>
        ))}
      </div>
    </section>
  );
}

function EventPanel({ events }: { events: HubEvent[] }) {
  return (
    <section className="panel">
      <div className="section-head">
        <h2>Events</h2>
        <span>{events.length} recorded</span>
      </div>
      <div className="alert-strip">
        {events.length === 0 && <div className="empty">No API events recorded</div>}
        {events.slice(0, 8).map(event => (
          <div className={`alert ${event.severity}`} key={event.id}>
            <AlertTriangle size={15} />
            <div>
              <strong>{event.event}</strong>
              <small>{event.message}{event.subject_id ? ` · ${shortHex(event.subject_id)}` : ''}</small>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

function InvoiceActions({ state, runAction, busy }: { state: NodeState; runAction: RunAction; busy: boolean }) {
  const [amount, setAmount] = useState('');
  const [description, setDescription] = useState('');
  const [expirySecs, setExpirySecs] = useState('3600');
  const [paymentMode, setPaymentMode] = useState<'preimage' | 'hash'>('preimage');
  const [paymentSecret, setPaymentSecret] = useState('');
  const [channelId, setChannelId] = useState('');
  const [decodeText, setDecodeText] = useState('');
  const [receiveInvoiceId, setReceiveInvoiceId] = useState('');
  const [settleInvoiceId, setSettleInvoiceId] = useState('');
  const [settlePreimage, setSettlePreimage] = useState('');

  const submitCreate = (event: FormEvent) => {
    event.preventDefault();
    void runAction('Create invoice', async () => {
      const body = {
        amount: assertPositiveInteger(amount, 'Amount'),
        description: requiredText(description, 'Description'),
        expiry_secs: Number(assertPositiveInteger(expirySecs, 'Expiry seconds')),
        channel_id: channelId.trim() ? assertHex32(channelId, 'Channel id') : undefined,
        payment_preimage: paymentMode === 'preimage' ? assertHex32(paymentSecret, 'Payment preimage') : undefined,
        payment_hash: paymentMode === 'hash' ? assertHex32(paymentSecret, 'Payment hash') : undefined,
        asset: { kind: 'ckb' },
      };
      return postAction('/api/invoices', body);
    });
  };

  const submitDecode = (event: FormEvent) => {
    event.preventDefault();
    void runAction('Decode invoice', () => postAction('/api/invoices/decode', { encoded_invoice: requiredText(decodeText, 'Encoded invoice') }));
  };

  const submitReceive = (event: FormEvent) => {
    event.preventDefault();
    void runAction('Receive invoice', () => {
      const invoiceId = assertHex32(receiveInvoiceId, 'Invoice id');
      return postAction(`/api/invoices/${invoiceId}/receive`);
    });
  };

  const submitSettle = (event: FormEvent) => {
    event.preventDefault();
    void runAction('Settle invoice', () => {
      const invoiceId = assertHex32(settleInvoiceId, 'Invoice id');
      const paymentPreimage = assertHex32(settlePreimage, 'Payment preimage');
      return postAction(`/api/invoices/${invoiceId}/settle`, { payment_preimage: paymentPreimage });
    });
  };

  return (
    <div className="drawer-section">
      <h2>Invoice Layer</h2>
      <form onSubmit={submitCreate} className="form-grid">
        <label>Amount<input value={amount} onChange={event => setAmount(event.target.value)} /></label>
        <label>Description<input value={description} onChange={event => setDescription(event.target.value)} /></label>
        <label>Expiry seconds<input value={expirySecs} onChange={event => setExpirySecs(event.target.value)} /></label>
        <label>Payment input
          <select value={paymentMode} onChange={event => setPaymentMode(event.target.value as 'preimage' | 'hash')}>
            <option value="preimage">preimage</option>
            <option value="hash">hash</option>
          </select>
        </label>
        <label>{paymentMode === 'preimage' ? 'Payment preimage' : 'Payment hash'}<input value={paymentSecret} onChange={event => setPaymentSecret(event.target.value)} /></label>
        <label>Channel id<input value={channelId} onChange={event => setChannelId(event.target.value)} /></label>
        <button disabled={busy}><Plus size={15} /> Create</button>
      </form>

      <form onSubmit={submitDecode} className="form-grid form-section">
        <label>Encoded invoice<textarea value={decodeText} onChange={event => setDecodeText(event.target.value)} /></label>
        <button disabled={busy}><ReceiptText size={15} /> Decode</button>
      </form>

      <form onSubmit={submitReceive} className="form-grid form-section">
        <label>Invoice id<input value={receiveInvoiceId} onChange={event => setReceiveInvoiceId(event.target.value)} /></label>
        <button disabled={busy}><Database size={15} /> Mark received</button>
      </form>

      <form onSubmit={submitSettle} className="form-grid form-section">
        <label>Invoice id<input value={settleInvoiceId} onChange={event => setSettleInvoiceId(event.target.value)} /></label>
        <label>Payment preimage<input value={settlePreimage} onChange={event => setSettlePreimage(event.target.value)} /></label>
        <button disabled={busy}><BadgeCheck size={15} /> Settle</button>
      </form>

      {state.invoices[0] && (
        <button className="copy-button" onClick={() => navigator.clipboard.writeText(state.invoices[0].encoded_invoice)} disabled={busy}>
          <Copy size={15} /> Copy latest invoice
        </button>
      )}
    </div>
  );
}

function ChannelActions({ state, runAction, busy }: { state: NodeState; runAction: RunAction; busy: boolean }) {
  const [channelId, setChannelId] = useState('');
  const [counterpartyNodeId, setCounterpartyNodeId] = useState('');
  const [counterpartyAlias, setCounterpartyAlias] = useState('');
  const [fundingContextId, setFundingContextId] = useState('');
  const [local, setLocal] = useState('');
  const [remote, setRemote] = useState('');
  const [pending, setPending] = useState('0');
  const [sponsorBudget, setSponsorBudget] = useState('');
  const [selectedChannelId, setSelectedChannelId] = useState('');
  const [spliceEpoch, setSpliceEpoch] = useState('');
  const [spliceContextId, setSpliceContextId] = useState('');
  const [publishContextId, setPublishContextId] = useState('');
  const [publishStateNumber, setPublishStateNumber] = useState('');

  const submitOpen = (event: FormEvent) => {
    event.preventDefault();
    void runAction('Open channel', () => postAction('/api/channels', channelBody({
      channelId,
      counterpartyNodeId,
      counterpartyAlias,
      fundingContextId,
      local,
      remote,
      pending,
      sponsorBudget,
    })));
  };

  const submitSplice = (event: FormEvent) => {
    event.preventDefault();
    void runAction('Splice channel', () => {
      const id = assertHex32(selectedChannelId, 'Channel id');
      return postAction(`/api/channels/${id}/splice`, {
        new_funding_epoch: Number(assertPositiveInteger(spliceEpoch, 'New funding epoch')),
        new_funding_context_id: assertHex32(spliceContextId, 'New funding context id'),
      });
    });
  };

  const submitPublish = (event: FormEvent) => {
    event.preventDefault();
    void runAction('Publish state', () => {
      const id = assertHex32(selectedChannelId, 'Channel id');
      return postAction(`/api/channels/${id}/publish`, {
        funding_context_id: assertHex32(publishContextId, 'Funding context id'),
        state_number: Number(assertPositiveInteger(publishStateNumber, 'State number')),
      });
    });
  };

  const submitFinalise = (event: FormEvent) => {
    event.preventDefault();
    void runAction('Finalise channel', () => {
      const id = assertHex32(selectedChannelId, 'Channel id');
      return postAction(`/api/channels/${id}/finalise`);
    });
  };

  return (
    <div className="drawer-section">
      <h2>Node Layer</h2>
      <form onSubmit={submitOpen} className="form-grid">
        <label>Channel id<input value={channelId} onChange={event => setChannelId(event.target.value)} /></label>
        <label>Counterparty node id<input value={counterpartyNodeId} onChange={event => setCounterpartyNodeId(event.target.value)} /></label>
        <label>Counterparty alias<input value={counterpartyAlias} onChange={event => setCounterpartyAlias(event.target.value)} /></label>
        <label>Funding context id<input value={fundingContextId} onChange={event => setFundingContextId(event.target.value)} /></label>
        <label>Local capacity<input value={local} onChange={event => setLocal(event.target.value)} /></label>
        <label>Remote capacity<input value={remote} onChange={event => setRemote(event.target.value)} /></label>
        <label>Pending capacity<input value={pending} onChange={event => setPending(event.target.value)} /></label>
        <label>Sponsor budget<input value={sponsorBudget} onChange={event => setSponsorBudget(event.target.value)} /></label>
        <button disabled={busy}><GitBranch size={15} /> Open channel</button>
      </form>

      <form onSubmit={submitSplice} className="form-grid form-section">
        <ChannelSelect channels={state.channels} value={selectedChannelId} onChange={setSelectedChannelId} />
        <label>New funding epoch<input value={spliceEpoch} onChange={event => setSpliceEpoch(event.target.value)} /></label>
        <label>New funding context id<input value={spliceContextId} onChange={event => setSpliceContextId(event.target.value)} /></label>
        <button disabled={busy || state.channels.length === 0}><Split size={15} /> Splice</button>
      </form>

      <form onSubmit={submitPublish} className="form-grid form-section">
        <ChannelSelect channels={state.channels} value={selectedChannelId} onChange={setSelectedChannelId} />
        <label>Funding context id<input value={publishContextId} onChange={event => setPublishContextId(event.target.value)} /></label>
        <label>State number<input value={publishStateNumber} onChange={event => setPublishStateNumber(event.target.value)} /></label>
        <button disabled={busy || state.channels.length === 0}><RadioTower size={15} /> Publish</button>
      </form>

      <form onSubmit={submitFinalise} className="form-grid form-section">
        <ChannelSelect channels={state.channels} value={selectedChannelId} onChange={setSelectedChannelId} />
        <button disabled={busy || state.channels.length === 0}><CheckCircle2 size={15} /> Finalise</button>
      </form>
    </div>
  );
}

function FactoryActions({ state, runAction, busy }: { state: NodeState; runAction: RunAction; busy: boolean }) {
  const [factoryId, setFactoryId] = useState('');
  const [participants, setParticipants] = useState('');
  const [reserve, setReserve] = useState('');
  const [selectedFactoryId, setSelectedFactoryId] = useState('');
  const [newUpdateNumber, setNewUpdateNumber] = useState('');
  const [childChannelId, setChildChannelId] = useState('');
  const [childCounterpartyNodeId, setChildCounterpartyNodeId] = useState('');
  const [childCounterpartyAlias, setChildCounterpartyAlias] = useState('');
  const [childFundingContextId, setChildFundingContextId] = useState('');
  const [childLocal, setChildLocal] = useState('');
  const [childRemote, setChildRemote] = useState('');
  const [childPending, setChildPending] = useState('0');
  const [childSponsorBudget, setChildSponsorBudget] = useState('');

  const submitOpen = (event: FormEvent) => {
    event.preventDefault();
    void runAction('Open factory', () => {
      const participant_node_ids = participants.split(',').map(value => assertHex32(value, 'Participant node id'));
      return postAction('/api/factories', {
        factory_id: assertHex32(factoryId, 'Factory id'),
        participant_node_ids,
        reserve: assertPositiveInteger(reserve, 'Reserve'),
        asset: { kind: 'ckb' },
      });
    });
  };

  const submitAdvance = (event: FormEvent) => {
    event.preventDefault();
    void runAction('Advance factory', () => {
      const id = assertHex32(selectedFactoryId, 'Factory id');
      return postAction(`/api/factories/${id}/advance`, {
        new_update_number: Number(assertPositiveInteger(newUpdateNumber, 'New update number')),
      });
    });
  };

  const submitMaterialise = (event: FormEvent) => {
    event.preventDefault();
    void runAction('Materialise factory child', () => {
      const id = assertHex32(selectedFactoryId, 'Factory id');
      return postAction(`/api/factories/${id}/materialise-child`, channelBody({
        channelId: childChannelId,
        counterpartyNodeId: childCounterpartyNodeId,
        counterpartyAlias: childCounterpartyAlias,
        fundingContextId: childFundingContextId,
        local: childLocal,
        remote: childRemote,
        pending: childPending,
        sponsorBudget: childSponsorBudget,
        child: true,
      }));
    });
  };

  return (
    <div className="drawer-section">
      <h2>Factory Layer</h2>
      <form onSubmit={submitOpen} className="form-grid">
        <label>Factory id<input value={factoryId} onChange={event => setFactoryId(event.target.value)} /></label>
        <label>Participant node ids<textarea value={participants} onChange={event => setParticipants(event.target.value)} /></label>
        <label>Reserve<input value={reserve} onChange={event => setReserve(event.target.value)} /></label>
        <button disabled={busy}><Factory size={15} /> Open factory</button>
      </form>

      <form onSubmit={submitAdvance} className="form-grid form-section">
        <FactorySelect factories={state.factories} value={selectedFactoryId} onChange={setSelectedFactoryId} />
        <label>New update number<input value={newUpdateNumber} onChange={event => setNewUpdateNumber(event.target.value)} /></label>
        <button disabled={busy || state.factories.length === 0}><RefreshCw size={15} /> Advance</button>
      </form>

      <form onSubmit={submitMaterialise} className="form-grid form-section">
        <FactorySelect factories={state.factories} value={selectedFactoryId} onChange={setSelectedFactoryId} />
        <label>Child channel id<input value={childChannelId} onChange={event => setChildChannelId(event.target.value)} /></label>
        <label>Counterparty node id<input value={childCounterpartyNodeId} onChange={event => setChildCounterpartyNodeId(event.target.value)} /></label>
        <label>Counterparty alias<input value={childCounterpartyAlias} onChange={event => setChildCounterpartyAlias(event.target.value)} /></label>
        <label>Funding context id<input value={childFundingContextId} onChange={event => setChildFundingContextId(event.target.value)} /></label>
        <label>Local capacity<input value={childLocal} onChange={event => setChildLocal(event.target.value)} /></label>
        <label>Remote capacity<input value={childRemote} onChange={event => setChildRemote(event.target.value)} /></label>
        <label>Pending capacity<input value={childPending} onChange={event => setChildPending(event.target.value)} /></label>
        <label>Sponsor budget<input value={childSponsorBudget} onChange={event => setChildSponsorBudget(event.target.value)} /></label>
        <button disabled={busy || state.factories.length === 0}><Network size={15} /> Materialise child</button>
      </form>
    </div>
  );
}

function StateActions({ state, runAction, busy }: { state: NodeState; runAction: RunAction; busy: boolean }) {
  const [raw, setRaw] = useState('');

  const exportState = async () => {
    const file = await getStateFile();
    setRaw(JSON.stringify(file, null, 2));
  };

  const restoreState = () => {
    void runAction('Restore state file', () => replaceStateFile(JSON.parse(requiredText(raw, 'State file JSON'))));
  };

  return (
    <div className="drawer-section">
      <h2>State File</h2>
      <div className="state-path">
        <strong>{state.state_path || 'not loaded'}</strong>
        <small>Backed by the Morph Hub API process</small>
      </div>
      <button className="copy-button" onClick={exportState} disabled={busy}><FileJson size={15} /> Load state JSON</button>
      <textarea className="snapshot" value={raw} onChange={event => setRaw(event.target.value)} />
      <button className="danger-button" onClick={restoreState} disabled={busy || !raw.trim()}><Upload size={15} /> Restore state file</button>
    </div>
  );
}

function ChannelSelect({ channels, value, onChange }: { channels: ChannelRecord[]; value: string; onChange: (value: string) => void }) {
  return (
    <label>Channel id
      <select value={value} onChange={event => onChange(event.target.value)}>
        <option value="">select channel</option>
        {channels.map(channel => (
          <option key={channel.channel_id} value={channel.channel_id}>{shortHex(channel.channel_id)} · {channel.phase}</option>
        ))}
      </select>
    </label>
  );
}

function FactorySelect({ factories, value, onChange }: { factories: FactoryRecord[]; value: string; onChange: (value: string) => void }) {
  return (
    <label>Factory id
      <select value={value} onChange={event => onChange(event.target.value)}>
        <option value="">select factory</option>
        {factories.map(factory => (
          <option key={factory.factory_id} value={factory.factory_id}>{shortHex(factory.factory_id)} · update {factory.update_number}</option>
        ))}
      </select>
    </label>
  );
}

function channelBody(input: {
  channelId: string;
  counterpartyNodeId: string;
  counterpartyAlias: string;
  fundingContextId: string;
  local: string;
  remote: string;
  pending: string;
  sponsorBudget: string;
  child?: boolean;
}) {
  const base = {
    counterparty_node_id: assertHex32(input.counterpartyNodeId, 'Counterparty node id'),
    counterparty_alias: input.counterpartyAlias.trim() || undefined,
    funding_context_id: assertHex32(input.fundingContextId, 'Funding context id'),
    local: assertPositiveInteger(input.local, 'Local capacity'),
    remote: assertPositiveInteger(input.remote, 'Remote capacity'),
    pending: assertNonNegativeInteger(input.pending, 'Pending capacity'),
    sponsor_budget: Number(assertPositiveInteger(input.sponsorBudget, 'Sponsor budget')),
    asset: { kind: 'ckb' } satisfies Asset,
  };
  if (input.child) {
    return { ...base, child_channel_id: assertHex32(input.channelId, 'Child channel id') };
  }
  return { ...base, channel_id: assertHex32(input.channelId, 'Channel id') };
}

function requiredText(value: string, label: string): string {
  const trimmed = value.trim();
  if (!trimmed) throw new Error(`${label} must not be empty.`);
  return trimmed;
}

function balanceTotal(balance?: Balance): bigint {
  if (!balance) return 0n;
  return BigInt(balance.local) + BigInt(balance.remote) + BigInt(balance.pending);
}

function rpcTone(status: NodeState['rpc']['status']): 'good' | 'neutral' | 'warn' | 'bad' {
  if (status === 'connected') return 'good';
  if (status === 'not_configured') return 'neutral';
  if (status === 'degraded') return 'warn';
  return 'bad';
}

function rpcLabel(state: NodeState): string {
  if (state.rpc.status === 'not_configured') return 'rpc not configured';
  if (state.rpc.status === 'connected') return state.rpc.chain ? `${state.rpc.chain} connected` : 'rpc connected';
  return state.rpc.status;
}
