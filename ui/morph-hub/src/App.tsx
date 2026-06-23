import {
  Activity,
  AlertTriangle,
  BadgeCheck,
  Bell,
  Boxes,
  Database,
  Factory,
  FileJson,
  GitBranch,
  Landmark,
  LayoutDashboard,
  Network,
  Plus,
  RadioTower,
  ReceiptText,
  RefreshCw,
  ShieldCheck,
  Split,
  Upload,
  Users,
  WalletCards,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import type React from 'react';
import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { getState, getStateFile, postAction, replaceStateFile, connectPeer } from './api';
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
  Pubkey,
  assertHex32,
  assertIncludesPubkey,
  assertNonNegativeInteger,
  assertPositiveInteger,
  assertPubkey,
  assertRemotePubkey,
  emptyState,
  normaliseAsset,
  formatAmount,
  formatBalance,
  formatTime,
  assetLabel,
  parsePubkeyList,
  shortHex,
} from './domain';

type ActionPanel = 'peer' | 'invoice' | 'channel' | 'factory' | 'state';
type RunAction = (label: string, action: () => Promise<NodeState>) => Promise<void>;

const actionItems: { key: ActionPanel; label: string; Icon: LucideIcon }[] = [
  { key: 'peer', label: 'Peers', Icon: Users },
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

const sectionIds = {
  overview: 'section-overview',
  channels: 'section-channels',
  invoices: 'section-invoices',
  peers: 'section-peers',
  factories: 'section-factories',
  events: 'section-events',
} as const;

type SectionKey = keyof typeof sectionIds;

export function App() {
  const [state, setState] = useState<NodeState>(emptyState);
  const [activeAction, setActiveAction] = useState<ActionPanel>('invoice');
  const [status, setStatus] = useState('Loading Morph Hub API');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [activeSection, setActiveSection] = useState<SectionKey>('overview');
  const workspaceRef = useRef<HTMLElement | null>(null);

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

  // Track which section is in view for sidebar highlighting.
  useEffect(() => {
    const root = workspaceRef.current;
    if (!root) return;
    const sections: SectionKey[] = ['overview', 'channels', 'invoices', 'peers', 'factories', 'events'];
    const observer = new IntersectionObserver(
      entries => {
        const visible = entries
          .filter(entry => entry.isIntersecting)
          .sort((a, b) => b.intersectionRatio - a.intersectionRatio);
        if (visible[0]) {
          const id = (visible[0].target as HTMLElement).id;
          const match = (Object.keys(sectionIds) as SectionKey[]).find(key => sectionIds[key] === id);
          if (match) setActiveSection(match);
        }
      },
      { root, rootMargin: '-20% 0px -60% 0px', threshold: [0, 0.25, 0.5, 1] }
    );
    sections.forEach(key => {
      const el = root.querySelector(`#${sectionIds[key]}`);
      if (el) observer.observe(el);
    });
    return () => observer.disconnect();
  }, [state]);

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

  const scrollTo = (key: SectionKey) => {
    const root = workspaceRef.current;
    const el = root?.querySelector(`#${sectionIds[key]}`) as HTMLElement | null;
    el?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    setActiveSection(key);
  };

  const selectAction = (key: ActionPanel) => {
    setActiveAction(key);
    setError('');
    setStatus('State refreshed from Morph Hub API');
  };

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

        <nav className="nav">
          <span className="nav-label">Monitor</span>
          <NavButton
            Icon={LayoutDashboard}
            label="Overview"
            active={activeSection === 'overview'}
            onClick={() => scrollTo('overview')}
          />
          <NavButton
            Icon={GitBranch}
            label="Channels"
            count={state.channels.length}
            active={activeSection === 'channels'}
            onClick={() => scrollTo('channels')}
          />
          <NavButton
            Icon={ReceiptText}
            label="Invoices"
            count={state.invoices.length}
            active={activeSection === 'invoices'}
            onClick={() => scrollTo('invoices')}
          />
          <NavButton
            Icon={Users}
            label="Peers"
            count={state.peers.length}
            active={activeSection === 'peers'}
            onClick={() => scrollTo('peers')}
          />
          <NavButton
            Icon={Factory}
            label="Factories"
            count={state.factories.length}
            active={activeSection === 'factories'}
            onClick={() => scrollTo('factories')}
          />
          <NavButton
            Icon={Bell}
            label="Events"
            count={state.events.length}
            active={activeSection === 'events'}
            onClick={() => scrollTo('events')}
          />
        </nav>

        <div className="node-card">
          <span>Pubkey</span>
          <strong>{shortHex(state.pubkey) || '—'}</strong>
          <small>{state.node_id}</small>
        </div>
        <div className="node-card">
          <span>State file</span>
          <strong>{state.state_path ? state.state_path.split('/').pop() : 'not loaded'}</strong>
          <small>{state.state_path || '—'}</small>
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

      <section className="workspace" ref={workspaceRef}>
        <header className="topbar" id={sectionIds.overview}>
          <div>
            <h1>Morph Node <span className={`network-badge ${state.network}`}><span className="dot" />{state.network}</span></h1>
            <p>{status}</p>
          </div>
          <div className="topbar-status">
            <StatusPill tone={rpcTone(state.rpc.status)} icon={<ShieldCheck size={15} />} label={rpcLabel(state)} />
            <StatusPill tone="neutral" icon={<Boxes size={15} />} label={state.rpc.tip_height == null ? 'tip unavailable' : `tip ${state.rpc.tip_height}`} />
            <button className={`icon-button ${busy ? 'spinning' : ''}`} title="Refresh from API" onClick={() => runAction('Refresh', refresh)} disabled={busy}>
              <RefreshCw size={16} />
            </button>
          </div>
        </header>

        <div className="mobile-node-strip">
          <span>Pubkey</span>
          <strong>{shortHex(state.pubkey) || '—'}</strong>
          <small>{state.network}</small>
        </div>

        {error && <div className="error banner"><AlertTriangle size={15} />{error}</div>}

        <section className="metric-grid">
          <Metric label="Vault value" value={formatAmount(totals.vaultValue, { kind: 'ckb' })} icon={<Landmark size={16} />} />
          <Metric label="Sponsor budget" value={formatAmount(totals.sponsorBudget, { kind: 'ckb' })} icon={<WalletCards size={16} />} />
          <Metric label="Settling states" value={String(totals.settlingStates)} icon={<AlertTriangle size={16} />} tone={totals.settlingStates ? 'warn' : 'base'} />
          <Metric label="Factory reserve" value={formatAmount(totals.factoryReserve, { kind: 'ckb' })} icon={<Factory size={16} />} />
        </section>

        <FlowPanel state={state} />

        <section className="content-grid">
          <div id={sectionIds.channels}>
            <ChannelTable channels={state.channels} />
          </div>
          <div id={sectionIds.invoices}>
            <InvoicePanel invoices={state.invoices} />
          </div>
          <div id={sectionIds.peers}>
            <PeerPanel peers={state.peers} />
          </div>
          <div id={sectionIds.factories}>
            <FactoryPanel factories={state.factories} />
          </div>
          <div id={sectionIds.events}>
            <EventPanel events={state.events} />
          </div>
        </section>
      </section>

      <aside className="action-drawer">
        <div className="drawer-tabs">
          {actionItems.map(({ key, label, Icon }) => (
            <button
              className={activeAction === key ? 'selected' : ''}
              key={key}
              onClick={() => selectAction(key)}
              title={label}
              aria-label={label}
              disabled={busy}
            >
              <Icon size={15} />
            </button>
          ))}
        </div>
        {activeAction === 'peer' && <PeerActions state={state} runAction={runAction} busy={busy} />}
        {activeAction === 'invoice' && <InvoiceActions state={state} runAction={runAction} busy={busy} />}
        {activeAction === 'channel' && <ChannelActions state={state} runAction={runAction} busy={busy} />}
        {activeAction === 'factory' && <FactoryActions state={state} runAction={runAction} busy={busy} />}
        {activeAction === 'state' && <StateActions state={state} runAction={runAction} busy={busy} />}
      </aside>
    </main>
  );
}

function NavButton({
  Icon,
  label,
  count,
  active,
  onClick,
}: {
  Icon: LucideIcon;
  label: string;
  count?: number;
  active?: boolean;
  onClick: () => void;
}) {
  return (
    <button className={`nav-item ${active ? 'active' : ''}`} onClick={onClick}>
      <Icon size={16} />
      <span className="label">{label}</span>
      {count != null && count > 0 && <span className="count">{count}</span>}
    </button>
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
      <div className="metric-top">
        <span className="metric-icon">{icon}</span>
        <span className="metric-label">{label}</span>
      </div>
      <strong className="metric-value">{value}</strong>
    </article>
  );
}

function FlowPanel({ state }: { state: NodeState }) {
  const flows = state.required_flows.length ? state.required_flows : (Object.keys(flowLabels) as FlowKey[]);
  const complete = state.missing_flows.length === 0;
  return (
    <section className="flow-panel">
      <div className="section-head">
        <h2>Business Flow</h2>
        <span className={`badge ${complete ? 'complete' : 'remaining'}`}>
          {complete ? 'complete' : `${state.missing_flows.length} remaining`}
        </span>
      </div>
      <div className="flow-grid">
        {flows.map(flow => {
          const done = state.completed_flows.includes(flow);
          return (
            <div className={`flow-step ${done ? 'done' : ''}`} key={flow}>
              <span className="flow-dot">{done ? <BadgeCheck size={15} /> : <Activity size={13} />}</span>
              <div>
                <strong>{flowLabels[flow]}</strong>
                <small>{done ? 'recorded' : 'pending'}</small>
              </div>
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
        <span className="badge">{channels.length} tracked</span>
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
              <td><strong>{shortHex(channel.channel_id)}</strong><small>{shortHex(channel.counterparty_pubkey)}</small></td>
              <td><span className={`phase ${channel.phase}`}>{channel.phase}</span></td>
              <td className="mono">#{channel.state_number}</td>
              <td><strong>epoch {channel.funding_epoch}</strong><small>{shortHex(channel.funding_context_id)}</small></td>
              <td className="mono">{formatBalance(channel.balances[0])}</td>
              <td className="mono">{formatAmount(channel.sponsor_budget, { kind: 'ckb' })}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

function InvoicePanel({ invoices }: { invoices: InvoiceRecord[] }) {
  const openCount = invoices.filter(invoice => invoice.status === 'open').length;
  return (
    <section className="panel">
      <div className="section-head">
        <h2>Invoices</h2>
        <span className="badge">{openCount} open</span>
      </div>
      <div className="stack-list">
        {invoices.length === 0 && <div className="empty">No invoices in the hub state file</div>}
        {invoices.slice(0, 5).map(invoice => (
          <div className="list-row" key={invoice.invoice_id}>
            <div>
              <strong>{invoice.description || shortHex(invoice.invoice_id)}</strong>
              <small>{formatAmount(invoice.amount, invoice.asset)} · {assetLabel(invoice.asset)} · {shortHex(invoice.payment_hash)}</small>
              <small>expires {formatTime(invoice.expires_at_unix)}</small>
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
        <span className="badge">{peers.length} connected</span>
      </div>
      <div className="stack-list">
        {peers.length === 0 && <div className="empty">No peers in the hub state file</div>}
        {peers.slice(0, 5).map(peer => (
          <div className="list-row" key={peer.node_id}>
            <div>
              <strong>{peer.alias}</strong>
              <small>{shortHex(peer.pubkey)}</small>
              <small>node {shortHex(peer.node_id)}</small>
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
        <span className="badge">{factories.length} active</span>
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
        <span className="badge">{events.length} recorded</span>
      </div>
      <div className="alert-strip">
        {events.length === 0 && <div className="empty">No API events recorded</div>}
        {events.slice(0, 8).map(event => (
          <div className={`alert ${event.severity}`} key={event.id}>
            <AlertTriangle size={15} />
            <div>
              <strong>{event.event}</strong>
              <small>{event.message}{event.subject_id ? ` · ${shortHex(event.subject_id)}` : ''}</small>
              <small>{formatTime(event.created_at_unix)}</small>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

function PeerActions({ state, runAction, busy }: { state: NodeState; runAction: RunAction; busy: boolean }) {
  const [pubkey, setPubkey] = useState('');
  const [alias, setAlias] = useState('');

  const submit = (event: FormEvent) => {
    event.preventDefault();
    void runAction('Connect peer', () => connectPeer(assertRemotePubkey(pubkey, state.pubkey, 'Peer pubkey'), requiredText(alias, 'Alias')));
  };

  return (
    <div className="drawer-section">
      <h2>Peer Layer</h2>
      <form onSubmit={submit} className="form-grid">
        <label>Peer pubkey<input className="mono" value={pubkey} onChange={event => setPubkey(event.target.value)} /></label>
        <label>Alias<input value={alias} onChange={event => setAlias(event.target.value)} /></label>
        <button disabled={busy}><Users size={15} /> Connect peer</button>
      </form>

      <div className="form-section">
        <h3>Known peers ({state.peers.length})</h3>
        <div className="stack-list">
          {state.peers.length === 0 && <div className="empty">No peers connected</div>}
          {state.peers.map(peer => (
            <div className="list-row" key={peer.node_id}>
              <div>
                <strong>{peer.alias}</strong>
                <small>{shortHex(peer.pubkey)}</small>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function AssetSelect({ value, onChange }: { value: Asset; onChange: (asset: Asset) => void }) {
  const isXudt = value.kind === 'xudt';
  const typeHash = !isXudt ? '' : value.type_hash ?? '';
  const selectAsset = (kind: 'ckb' | 'xudt') => {
    onChange(kind === 'ckb' ? { kind: 'ckb' } : { kind: 'xudt', type_hash: typeHash ? (typeHash as Hex32) : undefined });
  };
  const updateHash = (raw: string) => {
    onChange({ kind: 'xudt', type_hash: (raw || undefined) as Hex32 | undefined });
  };
  return (
    <>
      <label>Asset
        <select value={value.kind} onChange={event => selectAsset(event.target.value as 'ckb' | 'xudt')}>
          <option value="ckb">CKB</option>
          <option value="xudt">xUDT</option>
        </select>
      </label>
      {isXudt && (
        <label>Type hash<input className="mono" value={typeHash} onChange={event => updateHash(event.target.value)} /></label>
      )}
    </>
  );
}

function InvoiceActions({ state, runAction, busy }: { state: NodeState; runAction: RunAction; busy: boolean }) {
  const [amount, setAmount] = useState('');
  const [description, setDescription] = useState('');
  const [expirySecs, setExpirySecs] = useState('3600');
  const [paymentMode, setPaymentMode] = useState<'preimage' | 'hash'>('preimage');
  const [paymentSecret, setPaymentSecret] = useState('');
  const [channelId, setChannelId] = useState('');
  const [asset, setAsset] = useState<Asset>({ kind: 'ckb' });
  const [decodeText, setDecodeText] = useState('');
  const [receiveInvoiceId, setReceiveInvoiceId] = useState('');
  const [settleInvoiceId, setSettleInvoiceId] = useState('');
  const [settlePreimage, setSettlePreimage] = useState('');
  const [copyStatus, setCopyStatus] = useState('');

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
        asset: normaliseAsset(asset),
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

  const copyLatestInvoice = async () => {
    const encodedInvoice = state.invoices[0]?.encoded_invoice;
    if (!encodedInvoice) return;
    setCopyStatus('');
    try {
      await navigator.clipboard.writeText(encodedInvoice);
      setCopyStatus('copied');
    } catch (err) {
      setCopyStatus(String((err as Error).message));
    }
  };

  return (
    <div className="drawer-section">
      <h2>Invoice Layer</h2>
      <form onSubmit={submitCreate} className="form-grid">
        <label>Amount<input className="mono" value={amount} onChange={event => setAmount(event.target.value)} /></label>
        <label>Description<input value={description} onChange={event => setDescription(event.target.value)} /></label>
        <label>Expiry seconds<input className="mono" value={expirySecs} onChange={event => setExpirySecs(event.target.value)} /></label>
        <label>Payment input
          <select value={paymentMode} onChange={event => setPaymentMode(event.target.value as 'preimage' | 'hash')}>
            <option value="preimage">preimage</option>
            <option value="hash">hash</option>
          </select>
        </label>
        <label>{paymentMode === 'preimage' ? 'Payment preimage' : 'Payment hash'}<input className="mono" value={paymentSecret} onChange={event => setPaymentSecret(event.target.value)} /></label>
        <label>Channel id<input className="mono" value={channelId} onChange={event => setChannelId(event.target.value)} /></label>
        <AssetSelect value={asset} onChange={setAsset} />
        <button disabled={busy}><Plus size={15} /> Create invoice</button>
      </form>

      <div className="form-section">
        <h3>Decode</h3>
        <form onSubmit={submitDecode} className="form-grid">
          <label>Encoded invoice<textarea className="mono" value={decodeText} onChange={event => setDecodeText(event.target.value)} /></label>
          <button disabled={busy}><ReceiptText size={15} /> Decode</button>
        </form>
      </div>

      <div className="form-section">
        <h3>Receive</h3>
        <form onSubmit={submitReceive} className="form-grid">
          <label>Invoice id<input className="mono" value={receiveInvoiceId} onChange={event => setReceiveInvoiceId(event.target.value)} /></label>
          <button disabled={busy}><Database size={15} /> Mark received</button>
        </form>
      </div>

      <div className="form-section">
        <h3>Settle</h3>
        <form onSubmit={submitSettle} className="form-grid">
          <label>Invoice id<input className="mono" value={settleInvoiceId} onChange={event => setSettleInvoiceId(event.target.value)} /></label>
          <label>Payment preimage<input className="mono" value={settlePreimage} onChange={event => setSettlePreimage(event.target.value)} /></label>
          <button disabled={busy}><BadgeCheck size={15} /> Settle</button>
        </form>
      </div>

      {state.invoices[0] && (
        <button className="copy-button" onClick={copyLatestInvoice} disabled={busy}>
          <ReceiptText size={15} /> Copy latest invoice
        </button>
      )}
      {copyStatus && <small className={copyStatus === 'copied' ? 'inline-ok' : 'inline-error'}>{copyStatus}</small>}
    </div>
  );
}

function ChannelActions({ state, runAction, busy }: { state: NodeState; runAction: RunAction; busy: boolean }) {
  const [channelId, setChannelId] = useState('');
  const [counterpartyPubkey, setCounterpartyPubkey] = useState('');
  const [counterpartyAlias, setCounterpartyAlias] = useState('');
  const [fundingContextId, setFundingContextId] = useState('');
  const [local, setLocal] = useState('');
  const [remote, setRemote] = useState('');
  const [pending, setPending] = useState('0');
  const [sponsorBudget, setSponsorBudget] = useState('');
  const [asset, setAsset] = useState<Asset>({ kind: 'ckb' });
  const [spliceChannelId, setSpliceChannelId] = useState('');
  const [publishChannelId, setPublishChannelId] = useState('');
  const [finaliseChannelId, setFinaliseChannelId] = useState('');
  const [spliceEpoch, setSpliceEpoch] = useState('');
  const [spliceContextId, setSpliceContextId] = useState('');
  const [publishContextId, setPublishContextId] = useState('');
  const [publishStateNumber, setPublishStateNumber] = useState('');
  const activeChannels = state.channels.filter(channel => channel.phase === 'active');
  const publishableChannels = state.channels.filter(channel => channel.phase === 'active' || channel.phase === 'settling');
  const settlingChannels = state.channels.filter(channel => channel.phase === 'settling');

  const submitOpen = (event: FormEvent) => {
    event.preventDefault();
    void runAction('Open channel', () => postAction('/api/channels', channelBody({
      channelId,
      counterpartyPubkey,
      counterpartyAlias,
      fundingContextId,
      local,
      remote,
      pending,
      sponsorBudget,
      asset,
      localPubkey: state.pubkey,
    })));
  };

  const submitSplice = (event: FormEvent) => {
    event.preventDefault();
    void runAction('Splice channel', () => {
      const id = assertHex32(spliceChannelId, 'Channel id');
      return postAction(`/api/channels/${id}/splice`, {
        new_funding_epoch: Number(assertPositiveInteger(spliceEpoch, 'New funding epoch')),
        new_funding_context_id: assertHex32(spliceContextId, 'New funding context id'),
      });
    });
  };

  const submitPublish = (event: FormEvent) => {
    event.preventDefault();
    void runAction('Publish state', () => {
      const id = assertHex32(publishChannelId, 'Channel id');
      return postAction(`/api/channels/${id}/publish`, {
        funding_context_id: assertHex32(publishContextId, 'Funding context id'),
        state_number: Number(assertPositiveInteger(publishStateNumber, 'State number')),
      });
    });
  };

  const submitFinalise = (event: FormEvent) => {
    event.preventDefault();
    void runAction('Finalise channel', () => {
      const id = assertHex32(finaliseChannelId, 'Channel id');
      return postAction(`/api/channels/${id}/finalise`);
    });
  };

  return (
    <div className="drawer-section">
      <h2>Node Layer</h2>
      <form onSubmit={submitOpen} className="form-grid">
        <label>Channel id<input className="mono" value={channelId} onChange={event => setChannelId(event.target.value)} /></label>
        <label>Counterparty pubkey<input className="mono" value={counterpartyPubkey} onChange={event => setCounterpartyPubkey(event.target.value)} /></label>
        <label>Counterparty alias<input value={counterpartyAlias} onChange={event => setCounterpartyAlias(event.target.value)} /></label>
        <label>Funding context id<input className="mono" value={fundingContextId} onChange={event => setFundingContextId(event.target.value)} /></label>
        <label>Local capacity<input className="mono" value={local} onChange={event => setLocal(event.target.value)} /></label>
        <label>Remote capacity<input className="mono" value={remote} onChange={event => setRemote(event.target.value)} /></label>
        <label>Pending capacity<input className="mono" value={pending} onChange={event => setPending(event.target.value)} /></label>
        <label>Sponsor budget<input className="mono" value={sponsorBudget} onChange={event => setSponsorBudget(event.target.value)} /></label>
        <AssetSelect value={asset} onChange={setAsset} />
        <button disabled={busy}><GitBranch size={15} /> Open channel</button>
      </form>

      <div className="form-section">
        <h3>Splice</h3>
        <form onSubmit={submitSplice} className="form-grid">
          <ChannelSelect label="Active channel" channels={activeChannels} value={spliceChannelId} onChange={setSpliceChannelId} />
          <label>New funding epoch<input className="mono" value={spliceEpoch} onChange={event => setSpliceEpoch(event.target.value)} /></label>
          <label>New funding context id<input className="mono" value={spliceContextId} onChange={event => setSpliceContextId(event.target.value)} /></label>
          <button disabled={busy || activeChannels.length === 0}><Split size={15} /> Splice</button>
        </form>
      </div>

      <div className="form-section">
        <h3>Publish state</h3>
        <form onSubmit={submitPublish} className="form-grid">
          <ChannelSelect label="Publishable channel" channels={publishableChannels} value={publishChannelId} onChange={setPublishChannelId} />
          <label>Funding context id<input className="mono" value={publishContextId} onChange={event => setPublishContextId(event.target.value)} /></label>
          <label>State number<input className="mono" value={publishStateNumber} onChange={event => setPublishStateNumber(event.target.value)} /></label>
          <button disabled={busy || publishableChannels.length === 0}><RadioTower size={15} /> Publish</button>
        </form>
      </div>

      <div className="form-section">
        <h3>Finalise</h3>
        <form onSubmit={submitFinalise} className="form-grid">
          <ChannelSelect label="Settling channel" channels={settlingChannels} value={finaliseChannelId} onChange={setFinaliseChannelId} />
          <button disabled={busy || settlingChannels.length === 0}><BadgeCheck size={15} /> Finalise channel</button>
        </form>
      </div>
    </div>
  );
}

function FactoryActions({ state, runAction, busy }: { state: NodeState; runAction: RunAction; busy: boolean }) {
  const [factoryId, setFactoryId] = useState('');
  const [participants, setParticipants] = useState('');
  const [reserve, setReserve] = useState('');
  const [factoryAsset, setFactoryAsset] = useState<Asset>({ kind: 'ckb' });
  const [selectedFactoryId, setSelectedFactoryId] = useState('');
  const [newUpdateNumber, setNewUpdateNumber] = useState('');
  const [childChannelId, setChildChannelId] = useState('');
  const [childCounterpartyPubkey, setChildCounterpartyPubkey] = useState('');
  const [childCounterpartyAlias, setChildCounterpartyAlias] = useState('');
  const [childFundingContextId, setChildFundingContextId] = useState('');
  const [childLocal, setChildLocal] = useState('');
  const [childRemote, setChildRemote] = useState('');
  const [childPending, setChildPending] = useState('0');
  const [childSponsorBudget, setChildSponsorBudget] = useState('');
  const [childAsset, setChildAsset] = useState<Asset>({ kind: 'ckb' });

  const submitOpen = (event: FormEvent) => {
    event.preventDefault();
    void runAction('Open factory', () => {
      const participant_pubkeys = parsePubkeyList(participants, 'Participant pubkeys');
      assertIncludesPubkey(participant_pubkeys, state.pubkey, 'Participant pubkeys');
      return postAction('/api/factories', {
        factory_id: assertHex32(factoryId, 'Factory id'),
        participant_pubkeys,
        reserve: assertPositiveInteger(reserve, 'Reserve'),
        asset: normaliseAsset(factoryAsset),
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
        counterpartyPubkey: childCounterpartyPubkey,
        counterpartyAlias: childCounterpartyAlias,
        fundingContextId: childFundingContextId,
        local: childLocal,
        remote: childRemote,
        pending: childPending,
        sponsorBudget: childSponsorBudget,
        asset: childAsset,
        localPubkey: state.pubkey,
        child: true,
      }));
    });
  };

  return (
    <div className="drawer-section">
      <h2>Factory Layer</h2>
      <form onSubmit={submitOpen} className="form-grid">
        <label>Factory id<input className="mono" value={factoryId} onChange={event => setFactoryId(event.target.value)} /></label>
        <label>Participant pubkeys<textarea className="mono" value={participants} onChange={event => setParticipants(event.target.value)} /></label>
        <label>Reserve<input className="mono" value={reserve} onChange={event => setReserve(event.target.value)} /></label>
        <AssetSelect value={factoryAsset} onChange={setFactoryAsset} />
        <button disabled={busy}><Factory size={15} /> Open factory</button>
      </form>

      <div className="form-section">
        <h3>Advance</h3>
        <form onSubmit={submitAdvance} className="form-grid">
          <FactorySelect factories={state.factories} value={selectedFactoryId} onChange={setSelectedFactoryId} />
          <label>New update number<input className="mono" value={newUpdateNumber} onChange={event => setNewUpdateNumber(event.target.value)} /></label>
          <button disabled={busy || state.factories.length === 0}><RefreshCw size={15} /> Advance</button>
        </form>
      </div>

      <div className="form-section">
        <h3>Materialise child</h3>
        <form onSubmit={submitMaterialise} className="form-grid">
          <FactorySelect factories={state.factories} value={selectedFactoryId} onChange={setSelectedFactoryId} />
          <label>Child channel id<input className="mono" value={childChannelId} onChange={event => setChildChannelId(event.target.value)} /></label>
          <label>Counterparty pubkey<input className="mono" value={childCounterpartyPubkey} onChange={event => setChildCounterpartyPubkey(event.target.value)} /></label>
          <label>Counterparty alias<input value={childCounterpartyAlias} onChange={event => setChildCounterpartyAlias(event.target.value)} /></label>
          <label>Funding context id<input className="mono" value={childFundingContextId} onChange={event => setChildFundingContextId(event.target.value)} /></label>
          <label>Local capacity<input className="mono" value={childLocal} onChange={event => setChildLocal(event.target.value)} /></label>
          <label>Remote capacity<input className="mono" value={childRemote} onChange={event => setChildRemote(event.target.value)} /></label>
          <label>Pending capacity<input className="mono" value={childPending} onChange={event => setChildPending(event.target.value)} /></label>
          <label>Sponsor budget<input className="mono" value={childSponsorBudget} onChange={event => setChildSponsorBudget(event.target.value)} /></label>
          <AssetSelect value={childAsset} onChange={setChildAsset} />
          <button disabled={busy || state.factories.length === 0}><Network size={15} /> Materialise child</button>
        </form>
      </div>
    </div>
  );
}

function StateActions({ state, runAction, busy }: { state: NodeState; runAction: RunAction; busy: boolean }) {
  const [raw, setRaw] = useState('');
  const [stateFileStatus, setStateFileStatus] = useState('');
  const [stateFileBusy, setStateFileBusy] = useState(false);

  const exportState = async () => {
    setStateFileBusy(true);
    setStateFileStatus('');
    try {
      const file = await getStateFile();
      setRaw(JSON.stringify(file, null, 2));
      setStateFileStatus('loaded');
    } catch (err) {
      setStateFileStatus(String((err as Error).message));
    } finally {
      setStateFileBusy(false);
    }
  };

  const restoreState = () => {
    setStateFileStatus('');
    void runAction('Restore state file', () => replaceStateFile(JSON.parse(requiredText(raw, 'State file JSON'))));
  };

  return (
    <div className="drawer-section">
      <h2>State File</h2>
      <div className="state-path">
        <strong>{state.state_path || 'not loaded'}</strong>
        <small>Backed by the Morph Hub API process</small>
      </div>
      <button className="copy-button" onClick={exportState} disabled={busy || stateFileBusy}><FileJson size={15} /> Load state JSON</button>
      {stateFileStatus && <small className={stateFileStatus === 'loaded' ? 'inline-ok' : 'inline-error'}>{stateFileStatus}</small>}
      <textarea className="mono" value={raw} onChange={event => setRaw(event.target.value)} />
      <button className="danger-button" onClick={restoreState} disabled={busy || !raw.trim()}><Upload size={15} /> Restore state file</button>
    </div>
  );
}

function ChannelSelect({
  channels,
  value,
  onChange,
  label = 'Channel id',
}: {
  channels: ChannelRecord[];
  value: string;
  onChange: (value: string) => void;
  label?: string;
}) {
  return (
    <label>{label}
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
  counterpartyPubkey: string;
  counterpartyAlias: string;
  fundingContextId: string;
  local: string;
  remote: string;
  pending: string;
  sponsorBudget: string;
  asset: Asset;
  localPubkey: Pubkey;
  child?: boolean;
}) {
  const base = {
    counterparty_pubkey: assertRemotePubkey(input.counterpartyPubkey, input.localPubkey, 'Counterparty pubkey'),
    counterparty_alias: input.counterpartyAlias.trim() || undefined,
    funding_context_id: assertHex32(input.fundingContextId, 'Funding context id'),
    local: assertPositiveInteger(input.local, 'Local capacity'),
    remote: assertPositiveInteger(input.remote, 'Remote capacity'),
    pending: assertNonNegativeInteger(input.pending, 'Pending capacity'),
    sponsor_budget: Number(assertPositiveInteger(input.sponsorBudget, 'Sponsor budget')),
    asset: normaliseAsset(input.asset),
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
