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
import { getState, getStateFile, postAction, replaceStateFile, connectPeer, hasApiToken, openEventStream, setApiToken } from './api';
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
  RecordProvenance,
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
type LiveMode = 'starting' | 'sse' | 'sse-reconnecting' | 'polling' | 'polling-auth' | 'offline';

const LIVE_POLL_INTERVAL_MS = 5_000;

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
  const [liveMode, setLiveMode] = useState<LiveMode>('starting');
  const [authTokenPresent, setAuthTokenPresent] = useState(hasApiToken());
  const [requiresToken, setRequiresToken] = useState(false);
  const [tokenDraft, setTokenDraft] = useState('');
  const [initialStateLoaded, setInitialStateLoaded] = useState(false);
  const [activeSection, setActiveSection] = useState<SectionKey>('overview');
  const workspaceRef = useRef<HTMLElement | null>(null);
  const latestEventIdRef = useRef(0);

  const applyState = useCallback((next: NodeState) => {
    latestEventIdRef.current = latestEventId(next.events);
    setState(next);
  }, []);

  const refresh = useCallback(async () => {
    const next = await getState();
    applyState(next);
    setError('');
    setRequiresToken(false);
    setInitialStateLoaded(true);
    setStatus('State refreshed from Morph Hub API');
    return next;
  }, [applyState]);

  useEffect(() => {
    refresh().catch(err => {
      const message = String((err as Error).message);
      setRequiresToken(isAuthTokenError(message));
      setInitialStateLoaded(false);
      setError(message);
      setStatus('Morph Hub API is not reachable');
      setLiveMode('offline');
    });
  }, [refresh]);

  useEffect(() => {
    let stopped = false;
    if (!initialStateLoaded) {
      return () => {
        stopped = true;
      };
    }
    const refreshFromLive = async (message: string) => {
      const previousEventId = latestEventIdRef.current;
      try {
        const next = await getState();
        if (stopped) return;
        const nextEventId = latestEventId(next.events);
        applyState(next);
        setError('');
        if (nextEventId !== previousEventId) {
          setStatus(message);
        }
      } catch (err) {
        if (stopped) return;
        const message = String((err as Error).message);
        setLiveMode('offline');
        setRequiresToken(isAuthTokenError(message));
        setInitialStateLoaded(false);
        setError(message);
      }
    };

    const eventSource = openEventStream();
    if (eventSource) {
      setLiveMode('sse-reconnecting');
      const onHubEvent = () => {
        void refreshFromLive('Live event received from Morph Hub');
      };
      eventSource.onopen = () => {
        if (!stopped) setLiveMode('sse');
      };
      eventSource.onerror = () => {
        if (!stopped) setLiveMode('sse-reconnecting');
      };
      eventSource.addEventListener('morph-hub-event', onHubEvent);
      return () => {
        stopped = true;
        eventSource.removeEventListener('morph-hub-event', onHubEvent);
        eventSource.close();
      };
    }

    setLiveMode(authTokenPresent ? 'polling-auth' : 'polling');
    const interval = window.setInterval(() => {
      if (document.visibilityState !== 'hidden') {
        void refreshFromLive('State changed during live polling');
      }
    }, LIVE_POLL_INTERVAL_MS);
    return () => {
      stopped = true;
      window.clearInterval(interval);
    };
  }, [applyState, authTokenPresent, initialStateLoaded]);

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

  const flowDataLoaded = state.required_flows.length > 0;
  const completedCount = state.completed_flows.length;
  const requiredCount = flowDataLoaded ? state.required_flows.length : 1;
  const flowCoverage = flowDataLoaded ? Math.round((completedCount / requiredCount) * 100) : 0;
  const authRequired = requiresToken || state.security.auth_required;
  const activeActionLabel = actionItems.find(item => item.key === activeAction)?.label ?? 'Actions';
  const orderedEvents = useMemo(() => sortEventsNewestFirst(state.events), [state.events]);
  const orderedChannels = useMemo(() => sortChannelsForOperator(state.channels, state.events), [state.channels, state.events]);
  const orderedPeers = useMemo(() => sortPeersForOperator(state.peers, state.events), [state.peers, state.events]);
  const orderedFactories = useMemo(() => sortFactoriesForOperator(state.factories, state.events), [state.factories, state.events]);

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

  const submitApiToken = (event: FormEvent) => {
    event.preventDefault();
    setApiToken(tokenDraft);
    setAuthTokenPresent(hasApiToken());
    setRequiresToken(false);
    setError('');
    setStatus('API token stored for this browser session');
    refresh().catch(err => {
      const message = String((err as Error).message);
      setRequiresToken(isAuthTokenError(message));
      setInitialStateLoaded(false);
      setError(message);
      setStatus('API token rejected');
      setLiveMode('offline');
    });
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
            testId="nav-overview"
            active={activeSection === 'overview'}
            onClick={() => scrollTo('overview')}
          />
          <NavButton
            Icon={GitBranch}
            label="Channels"
            testId="nav-channels"
            count={state.channels.length}
            active={activeSection === 'channels'}
            onClick={() => scrollTo('channels')}
          />
          <NavButton
            Icon={ReceiptText}
            label="Invoices"
            testId="nav-invoices"
            count={state.invoices.length}
            active={activeSection === 'invoices'}
            onClick={() => scrollTo('invoices')}
          />
          <NavButton
            Icon={Users}
            label="Peers"
            testId="nav-peers"
            count={state.peers.length}
            active={activeSection === 'peers'}
            onClick={() => scrollTo('peers')}
          />
          <NavButton
            Icon={Factory}
            label="Factories"
            testId="nav-factories"
            count={state.factories.length}
            active={activeSection === 'factories'}
            onClick={() => scrollTo('factories')}
          />
          <NavButton
            Icon={Bell}
            label="Events"
            testId="nav-events"
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
            <strong>{flowDataLoaded ? `${completedCount}/${state.required_flows.length}` : 'not loaded'}</strong>
          </div>
          <div className="meter">
            <span style={{ width: `${flowCoverage}%` }} />
          </div>
          <small>{flowDataLoaded ? (state.missing_flows.length === 0 ? 'All required flows recorded' : `${state.missing_flows.length} flows remaining`) : 'Waiting for Hub API'}</small>
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
            <StatusPill tone={authRequired && !requiresToken ? 'good' : 'warn'} icon={<ShieldCheck size={15} />} label={authRequired ? 'auth required' : 'loopback only'} />
            <StatusPill tone={liveTone(liveMode)} icon={<RadioTower size={15} />} label={liveLabel(liveMode)} />
            <StatusPill tone="neutral" icon={<Boxes size={15} />} label={state.rpc.tip_height == null ? 'tip unavailable' : `tip ${state.rpc.tip_height}`} />
            <button className={`icon-button ${busy ? 'spinning' : ''}`} title="Refresh from API" data-testid="hub-refresh" onClick={() => runAction('Refresh', refresh)} disabled={busy}>
              <RefreshCw size={16} />
            </button>
          </div>
        </header>

        <NodeInfoStrip state={state} liveMode={liveMode} flowDataLoaded={flowDataLoaded} />

        {error && <div className="error banner"><AlertTriangle size={15} />{error}</div>}
        {requiresToken && (
          <form className="auth-banner" onSubmit={submitApiToken}>
            <ShieldCheck size={15} />
            <label>
              Morph Hub API token
              <input
                data-testid="api-token-input"
                type="password"
                value={tokenDraft}
                onChange={event => setTokenDraft(event.target.value)}
                autoComplete="off"
              />
            </label>
            <button data-testid="api-token-submit" disabled={!tokenDraft.trim() || busy}>Unlock API</button>
          </form>
        )}
        <div className={`provenance-banner ${state.rpc.status === 'connected' ? 'connected' : 'local'}`} data-testid="provenance-banner">
          <ShieldCheck size={15} />
          <div>
            <strong>{state.rpc.status === 'connected' ? 'CKB RPC connected, records still require evidence' : 'Local Hub state only'}</strong>
            <span>{state.provenance.message}</span>
          </div>
        </div>

        <section className="metric-grid">
          <Metric label="Vault value" value={formatAmount(totals.vaultValue, { kind: 'ckb' })} icon={<Landmark size={16} />} />
          <Metric label="Sponsor budget" value={formatAmount(totals.sponsorBudget, { kind: 'ckb' })} icon={<WalletCards size={16} />} />
          <Metric label="Settling states" value={String(totals.settlingStates)} icon={<AlertTriangle size={16} />} tone={totals.settlingStates ? 'warn' : 'base'} />
          <Metric label="Factory reserve" value={formatAmount(totals.factoryReserve, { kind: 'ckb' })} icon={<Factory size={16} />} />
        </section>

        <FlowPanel state={state} />

        <section className="content-grid">
          <div id={sectionIds.channels}>
            <ChannelTable channels={orderedChannels} />
          </div>
          <div id={sectionIds.invoices}>
            <InvoicePanel invoices={state.invoices} />
          </div>
          <div id={sectionIds.peers}>
            <PeerPanel peers={orderedPeers} />
          </div>
          <div id={sectionIds.factories}>
            <FactoryPanel factories={orderedFactories} />
          </div>
          <div id={sectionIds.events}>
            <EventPanel events={orderedEvents} />
          </div>
        </section>
      </section>

      <aside className="action-drawer">
        <div className="drawer-head">
          <span>Operate</span>
          <strong>{activeActionLabel}</strong>
        </div>
        <div className="drawer-tabs">
          {actionItems.map(({ key, label, Icon }) => (
            <button
              className={activeAction === key ? 'selected' : ''}
              key={key}
              onClick={() => selectAction(key)}
              title={label}
              aria-label={label}
              data-testid={`action-${key}`}
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
  testId,
  count,
  active,
  onClick,
}: {
  Icon: LucideIcon;
  label: string;
  testId: string;
  count?: number;
  active?: boolean;
  onClick: () => void;
}) {
  return (
    <button className={`nav-item ${active ? 'active' : ''}`} data-testid={testId} onClick={onClick}>
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

function NodeInfoStrip({
  state,
  liveMode,
  flowDataLoaded,
}: {
  state: NodeState;
  liveMode: LiveMode;
  flowDataLoaded: boolean;
}) {
  const flowsValue = flowDataLoaded ? `${state.completed_flows.length}/${state.required_flows.length}` : 'not loaded';
  const stateFile = state.state_path ? state.state_path.split('/').pop() || state.state_path : 'not loaded';
  return (
    <div className="node-info-strip" data-testid="node-info-strip">
      <NodeInfoPill Icon={Network} label="Pubkey" value={shortHex(state.pubkey) || 'not loaded'} title={state.pubkey} monospace />
      <NodeInfoPill Icon={Database} label="Node id" value={shortHex(state.node_id)} title={state.node_id} monospace />
      <span className="node-info-separator" />
      <NodeInfoPill Icon={Activity} label="Flows" value={flowsValue} tone={flowDataLoaded && state.missing_flows.length === 0 ? 'good' : 'warn'} />
      <NodeInfoPill Icon={GitBranch} label="Channels" value={String(state.channels.length)} />
      <NodeInfoPill Icon={Users} label="Peers" value={String(state.peers.length)} />
      <NodeInfoPill Icon={ReceiptText} label="Invoices" value={String(state.invoices.length)} />
      <NodeInfoPill Icon={Factory} label="Factories" value={String(state.factories.length)} />
      <span className="node-info-separator" />
      <NodeInfoPill Icon={ShieldCheck} label="RPC" value={rpcLabel(state)} tone={rpcTone(state.rpc.status)} />
      <NodeInfoPill Icon={RadioTower} label="Live" value={liveLabel(liveMode).replace('live ', '')} tone={liveTone(liveMode)} />
      <NodeInfoPill Icon={FileJson} label="State" value={stateFile} title={state.state_path} monospace />
    </div>
  );
}

function NodeInfoPill({
  Icon,
  label,
  value,
  tone = 'neutral',
  title,
  monospace = false,
}: {
  Icon: LucideIcon;
  label: string;
  value: string;
  tone?: 'good' | 'neutral' | 'warn' | 'bad';
  title?: string;
  monospace?: boolean;
}) {
  return (
    <span className={`node-info-pill ${tone}`} title={title || value}>
      <span className="node-info-icon"><Icon size={14} /></span>
      <span className="node-info-label">{label}</span>
      <strong className={monospace ? 'mono' : ''}>{value}</strong>
    </span>
  );
}

function ProvenanceBadge({ provenance }: { provenance: RecordProvenance }) {
  return (
    <span className={`provenance-badge ${provenance.chain_status}`} title={provenance.message}>
      {provenance.label}
    </span>
  );
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
  const flowDataLoaded = state.required_flows.length > 0;
  const flows = flowDataLoaded ? state.required_flows : (Object.keys(flowLabels) as FlowKey[]);
  const complete = flowDataLoaded && state.missing_flows.length === 0;
  return (
    <section className="flow-panel">
      <div className="section-head">
        <h2>Business Flow</h2>
        <span className={`badge ${complete ? 'complete' : 'remaining'}`}>
          {!flowDataLoaded ? 'not loaded' : complete ? 'complete' : `${state.missing_flows.length} remaining`}
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
            <th>Source</th>
          </tr>
        </thead>
        <tbody>
          {channels.length === 0 && (
            <tr><td colSpan={7} className="empty">No channels in the hub state file</td></tr>
          )}
          {channels.map(channel => (
            <tr key={channel.channel_id}>
              <td><strong>{shortHex(channel.channel_id)}</strong><small>{shortHex(channel.counterparty_pubkey)}</small></td>
              <td><span className={`phase ${channel.phase}`}>{channel.phase}</span></td>
              <td className="mono">#{channel.state_number}</td>
              <td><strong>epoch {channel.funding_epoch}</strong><small>{shortHex(channel.funding_context_id)}</small></td>
              <td className="mono">{formatBalance(channel.balances[0])}</td>
              <td className="mono">{formatAmount(channel.sponsor_budget, { kind: 'ckb' })}</td>
              <td><ProvenanceBadge provenance={channel.provenance} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

function InvoicePanel({ invoices }: { invoices: InvoiceRecord[] }) {
  const orderedInvoices = sortInvoicesNewestFirst(invoices);
  const openCount = invoices.filter(invoice => invoice.status === 'open').length;
  return (
    <section className="panel">
      <div className="section-head">
        <h2>Invoices</h2>
        <span className="badge">{openCount} open</span>
      </div>
      <div className="stack-list">
        {invoices.length === 0 && <div className="empty">No invoices in the hub state file</div>}
        {orderedInvoices.slice(0, 5).map(invoice => (
            <div className="list-row" key={invoice.invoice_id}>
              <div>
                <strong>{invoice.description || shortHex(invoice.invoice_id)}</strong>
                <small>{formatAmount(invoice.amount, invoice.asset)} · {assetLabel(invoice.asset)} · {shortHex(invoice.payment_hash)}</small>
                <small>expires {formatTime(invoice.expires_at_unix)}</small>
              </div>
              <div className="row-badges">
                <span className={`status ${invoice.status}`}>{invoice.status}</span>
                <ProvenanceBadge provenance={invoice.provenance} />
              </div>
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
            <ProvenanceBadge provenance={peer.provenance} />
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
            <div className="row-badges">
              <span className="amount">{formatBalance(factory.reserve_balances[0])}</span>
              <ProvenanceBadge provenance={factory.provenance} />
            </div>
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
      <div className="event-log">
        {events.length === 0 && <div className="empty">No API events recorded</div>}
        {events.slice(0, 10).map(event => (
          <div className={`event-entry ${event.severity}`} key={event.id}>
            <EventMark severity={event.severity} />
            <div className="event-main">
              <div className="event-line">
                <strong>{event.event}</strong>
                <time dateTime={new Date(event.created_at_unix * 1000).toISOString()}>{formatTime(event.created_at_unix)}</time>
              </div>
              <small>{event.message}</small>
              <div className="event-meta">
                {event.subject_id && <span className="mono">{shortHex(event.subject_id)}</span>}
                <ProvenanceBadge provenance={event.provenance} />
              </div>
            </div>
          </div>
        ))}
      </div>
    </section>
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
        <label>Peer pubkey<input className="mono" data-testid="peer-pubkey" value={pubkey} onChange={event => setPubkey(event.target.value)} /></label>
        <label>Alias<input data-testid="peer-alias" value={alias} onChange={event => setAlias(event.target.value)} /></label>
        <button data-testid="peer-connect" disabled={busy}><Users size={15} /> Connect peer</button>
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
  const [expirySecs, setExpirySecs] = useState('');
  const [paymentMode, setPaymentMode] = useState<'preimage' | 'hash'>('preimage');
  const [paymentSecret, setPaymentSecret] = useState('');
  const [channelId, setChannelId] = useState('');
  const [asset, setAsset] = useState<Asset>({ kind: 'ckb' });
  const [decodeText, setDecodeText] = useState('');
  const [receiveInvoiceId, setReceiveInvoiceId] = useState('');
  const [settleInvoiceId, setSettleInvoiceId] = useState('');
  const [settlePreimage, setSettlePreimage] = useState('');
  const [copyStatus, setCopyStatus] = useState('');
  const activeChannels = sortChannelsForOperator(state.channels, state.events).filter(channel => channel.phase === 'active');
  const latestActiveChannel = activeChannels[0];
  const latestOpenInvoice = newestInvoice(state.invoices.filter(invoice => invoice.status === 'open'));
  const latestSettleableInvoice = newestInvoice(
    state.invoices.filter(invoice => invoice.status === 'open' || invoice.status === 'received')
  );

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
    const encodedInvoice = latestSettleableInvoice?.encoded_invoice;
    if (!encodedInvoice) return;
    setCopyStatus('');
    try {
      await copyTextToClipboard(encodedInvoice);
      setCopyStatus('copied');
    } catch (err) {
      setCopyStatus(String((err as Error).message));
    }
  };

  return (
    <div className="drawer-section">
      <h2>Invoice Layer</h2>
      <form onSubmit={submitCreate} className="form-grid">
        <label>Amount<input className="mono" data-testid="invoice-amount" value={amount} onChange={event => setAmount(event.target.value)} /></label>
        <label>Description<input data-testid="invoice-description" value={description} onChange={event => setDescription(event.target.value)} /></label>
        <label>Expiry seconds<input className="mono" data-testid="invoice-expiry-secs" value={expirySecs} onChange={event => setExpirySecs(event.target.value)} /></label>
        <label>Payment input
          <select data-testid="invoice-payment-mode" value={paymentMode} onChange={event => setPaymentMode(event.target.value as 'preimage' | 'hash')}>
            <option value="preimage">preimage</option>
            <option value="hash">hash</option>
          </select>
        </label>
        <label>
          <span className="field-label-row">
            {paymentMode === 'preimage' ? 'Payment preimage' : 'Payment hash'}
            {paymentMode === 'preimage' && (
              <button type="button" className="field-action" data-testid="invoice-generate-payment-secret" onClick={() => setPaymentSecret(randomHex32())}>
                <RefreshCw size={12} /> Generate
              </button>
            )}
          </span>
          <input className="mono" data-testid="invoice-payment-secret" value={paymentSecret} onChange={event => setPaymentSecret(event.target.value)} />
        </label>
        <label>
          <span className="field-label-row">
            Channel id
            <button
              type="button"
              className="field-action"
              data-testid="invoice-use-active-channel"
              onClick={() => setChannelId(latestActiveChannel?.channel_id ?? '')}
              disabled={!latestActiveChannel}
            >
              <GitBranch size={12} /> Use active
            </button>
          </span>
          <input className="mono" data-testid="invoice-channel-id" value={channelId} onChange={event => setChannelId(event.target.value)} />
        </label>
        <AssetSelect value={asset} onChange={setAsset} />
        <button data-testid="invoice-create" disabled={busy}><Plus size={15} /> Create invoice</button>
      </form>

      <div className="form-section">
        <h3>Decode</h3>
        <form onSubmit={submitDecode} className="form-grid">
          <label>Encoded invoice<textarea className="mono" data-testid="invoice-decode-text" value={decodeText} onChange={event => setDecodeText(event.target.value)} /></label>
          <button data-testid="invoice-decode" disabled={busy}><ReceiptText size={15} /> Decode</button>
        </form>
      </div>

      <div className="form-section">
        <h3>Receive</h3>
        <form onSubmit={submitReceive} className="form-grid">
          <label>
            <span className="field-label-row">
              Invoice id
              <button type="button" className="field-action" data-testid="invoice-receive-latest" onClick={() => setReceiveInvoiceId(latestOpenInvoice?.invoice_id ?? '')} disabled={!latestOpenInvoice}>
                <ReceiptText size={12} /> Latest
              </button>
            </span>
            <input className="mono" data-testid="invoice-receive-id" value={receiveInvoiceId} onChange={event => setReceiveInvoiceId(event.target.value)} />
          </label>
          <button data-testid="invoice-receive" disabled={busy}><Database size={15} /> Mark received</button>
        </form>
      </div>

      <div className="form-section">
        <h3>Settle</h3>
        <form onSubmit={submitSettle} className="form-grid">
          <label>
            <span className="field-label-row">
              Invoice id
              <button type="button" className="field-action" data-testid="invoice-settle-latest" onClick={() => setSettleInvoiceId(latestSettleableInvoice?.invoice_id ?? '')} disabled={!latestSettleableInvoice}>
                <ReceiptText size={12} /> Latest
              </button>
            </span>
            <input className="mono" data-testid="invoice-settle-id" value={settleInvoiceId} onChange={event => setSettleInvoiceId(event.target.value)} />
          </label>
          <label>Payment preimage<input className="mono" data-testid="invoice-settle-preimage" value={settlePreimage} onChange={event => setSettlePreimage(event.target.value)} /></label>
          <button data-testid="invoice-settle" disabled={busy}><BadgeCheck size={15} /> Settle</button>
        </form>
      </div>

      {latestSettleableInvoice && (
        <button className="copy-button" data-testid="invoice-copy-latest" onClick={copyLatestInvoice} disabled={busy}>
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
  const [pending, setPending] = useState('');
  const [sponsorBudget, setSponsorBudget] = useState('');
  const [asset, setAsset] = useState<Asset>({ kind: 'ckb' });
  const [spliceChannelId, setSpliceChannelId] = useState('');
  const [publishChannelId, setPublishChannelId] = useState('');
  const [finaliseChannelId, setFinaliseChannelId] = useState('');
  const [spliceEpoch, setSpliceEpoch] = useState('');
  const [spliceContextId, setSpliceContextId] = useState('');
  const [publishContextId, setPublishContextId] = useState('');
  const [publishStateNumber, setPublishStateNumber] = useState('');
  const orderedChannels = sortChannelsForOperator(state.channels, state.events);
  const activeChannels = orderedChannels.filter(channel => channel.phase === 'active');
  const publishableChannels = orderedChannels.filter(channel => channel.phase === 'active' || channel.phase === 'settling');
  const settlingChannels = orderedChannels.filter(channel => channel.phase === 'settling');
  const selectedSpliceChannel = activeChannels.find(channel => channel.channel_id === spliceChannelId);
  const selectedPublishChannel = publishableChannels.find(channel => channel.channel_id === publishChannelId);

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

  const generateOpenChannelIds = () => {
    setChannelId(randomHex32());
    setFundingContextId(randomHex32());
  };

  const useSelectedSpliceDefaults = () => {
    if (!selectedSpliceChannel) return;
    setSpliceEpoch(String(selectedSpliceChannel.funding_epoch + 1));
    setSpliceContextId(randomHex32());
  };

  const useSelectedPublishDefaults = () => {
    if (!selectedPublishChannel) return;
    setPublishContextId(selectedPublishChannel.funding_context_id);
    setPublishStateNumber(String(selectedPublishChannel.state_number + 1));
  };

  return (
    <div className="drawer-section">
      <h2>Node Layer</h2>
      <form onSubmit={submitOpen} className="form-grid">
        <div className="field-action-row">
          <button type="button" className="field-action" data-testid="channel-generate-ids" onClick={generateOpenChannelIds}>
            <RefreshCw size={12} /> Generate ids
          </button>
        </div>
        <label>Channel id<input className="mono" data-testid="channel-id" value={channelId} onChange={event => setChannelId(event.target.value)} /></label>
        <label>Counterparty pubkey<input className="mono" data-testid="channel-counterparty-pubkey" value={counterpartyPubkey} onChange={event => setCounterpartyPubkey(event.target.value)} /></label>
        <label>Counterparty alias<input data-testid="channel-counterparty-alias" value={counterpartyAlias} onChange={event => setCounterpartyAlias(event.target.value)} /></label>
        <label>Funding context id<input className="mono" data-testid="channel-funding-context-id" value={fundingContextId} onChange={event => setFundingContextId(event.target.value)} /></label>
        <label>Local capacity<input className="mono" data-testid="channel-local" value={local} onChange={event => setLocal(event.target.value)} /></label>
        <label>Remote capacity<input className="mono" data-testid="channel-remote" value={remote} onChange={event => setRemote(event.target.value)} /></label>
        <label>Pending capacity<input className="mono" data-testid="channel-pending" value={pending} onChange={event => setPending(event.target.value)} /></label>
        <label>Sponsor budget<input className="mono" data-testid="channel-sponsor-budget" value={sponsorBudget} onChange={event => setSponsorBudget(event.target.value)} /></label>
        <AssetSelect value={asset} onChange={setAsset} />
        <button data-testid="channel-open" disabled={busy}><GitBranch size={15} /> Open channel</button>
      </form>

      <div className="form-section">
        <h3>Splice</h3>
        <form onSubmit={submitSplice} className="form-grid">
          <ChannelSelect testId="channel-splice-select" label="Active channel" channels={activeChannels} value={spliceChannelId} onChange={setSpliceChannelId} />
          <div className="field-action-row">
            <button type="button" className="field-action" data-testid="channel-splice-use-selected" onClick={useSelectedSpliceDefaults} disabled={!selectedSpliceChannel}>
              <RefreshCw size={12} /> Use selected
            </button>
          </div>
          <label>New funding epoch<input className="mono" data-testid="channel-splice-epoch" value={spliceEpoch} onChange={event => setSpliceEpoch(event.target.value)} /></label>
          <label>New funding context id<input className="mono" data-testid="channel-splice-context-id" value={spliceContextId} onChange={event => setSpliceContextId(event.target.value)} /></label>
          <button data-testid="channel-splice" disabled={busy || activeChannels.length === 0}><Split size={15} /> Splice</button>
        </form>
      </div>

      <div className="form-section">
        <h3>Publish state</h3>
        <form onSubmit={submitPublish} className="form-grid">
          <ChannelSelect testId="channel-publish-select" label="Publishable channel" channels={publishableChannels} value={publishChannelId} onChange={setPublishChannelId} />
          <div className="field-action-row">
            <button type="button" className="field-action" data-testid="channel-publish-use-selected" onClick={useSelectedPublishDefaults} disabled={!selectedPublishChannel}>
              <Activity size={12} /> Use selected
            </button>
          </div>
          <label>Funding context id<input className="mono" data-testid="channel-publish-context-id" value={publishContextId} onChange={event => setPublishContextId(event.target.value)} /></label>
          <label>State number<input className="mono" data-testid="channel-publish-state-number" value={publishStateNumber} onChange={event => setPublishStateNumber(event.target.value)} /></label>
          <button data-testid="channel-publish" disabled={busy || publishableChannels.length === 0}><RadioTower size={15} /> Publish</button>
        </form>
      </div>

      <div className="form-section">
        <h3>Finalise</h3>
        <form onSubmit={submitFinalise} className="form-grid">
          <ChannelSelect testId="channel-finalise-select" label="Settling channel" channels={settlingChannels} value={finaliseChannelId} onChange={setFinaliseChannelId} />
          <button data-testid="channel-finalise" disabled={busy || settlingChannels.length === 0}><BadgeCheck size={15} /> Finalise channel</button>
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
  const [childPending, setChildPending] = useState('');
  const [childSponsorBudget, setChildSponsorBudget] = useState('');
  const [childAsset, setChildAsset] = useState<Asset>({ kind: 'ckb' });
  const orderedFactories = sortFactoriesForOperator(state.factories, state.events);
  const selectedFactory = orderedFactories.find(factory => factory.factory_id === selectedFactoryId);

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

  const addLocalParticipant = () => {
    const entries = parsePubkeyDraft(participants);
    if (!entries.includes(state.pubkey)) {
      setParticipants([...entries, state.pubkey].join('\n'));
    }
  };

  const generateFactoryId = () => {
    setFactoryId(randomHex32());
  };

  const useSelectedFactoryUpdate = () => {
    if (!selectedFactory) return;
    setNewUpdateNumber(String(selectedFactory.update_number + 1));
  };

  const generateChildIds = () => {
    setChildChannelId(randomHex32());
    setChildFundingContextId(randomHex32());
  };

  return (
    <div className="drawer-section">
      <h2>Factory Layer</h2>
      <form onSubmit={submitOpen} className="form-grid">
        <label>
          <span className="field-label-row">
            Factory id
            <button type="button" className="field-action" data-testid="factory-generate-id" onClick={generateFactoryId}>
              <RefreshCw size={12} /> Generate
            </button>
          </span>
          <input className="mono" data-testid="factory-id" value={factoryId} onChange={event => setFactoryId(event.target.value)} />
        </label>
        <label>
          <span className="field-label-row">
            Participant pubkeys
            <button type="button" className="field-action" data-testid="factory-add-local-pubkey" onClick={addLocalParticipant} disabled={!state.pubkey}>
              <Plus size={12} /> Add local
            </button>
          </span>
          <textarea className="mono" data-testid="factory-participants" value={participants} onChange={event => setParticipants(event.target.value)} />
        </label>
        <label>Reserve<input className="mono" data-testid="factory-reserve" value={reserve} onChange={event => setReserve(event.target.value)} /></label>
        <AssetSelect value={factoryAsset} onChange={setFactoryAsset} />
        <button data-testid="factory-open" disabled={busy}><Factory size={15} /> Open factory</button>
      </form>

      <div className="form-section">
        <h3>Advance</h3>
        <form onSubmit={submitAdvance} className="form-grid">
          <FactorySelect testId="factory-advance-select" factories={orderedFactories} value={selectedFactoryId} onChange={setSelectedFactoryId} />
          <div className="field-action-row">
            <button type="button" className="field-action" data-testid="factory-advance-use-selected" onClick={useSelectedFactoryUpdate} disabled={!selectedFactory}>
              <Activity size={12} /> Use selected
            </button>
          </div>
          <label>New update number<input className="mono" data-testid="factory-new-update-number" value={newUpdateNumber} onChange={event => setNewUpdateNumber(event.target.value)} /></label>
          <button data-testid="factory-advance" disabled={busy || orderedFactories.length === 0}><RefreshCw size={15} /> Advance</button>
        </form>
      </div>

      <div className="form-section">
        <h3>Materialise child</h3>
        <form onSubmit={submitMaterialise} className="form-grid">
          <FactorySelect testId="factory-materialise-select" factories={orderedFactories} value={selectedFactoryId} onChange={setSelectedFactoryId} />
          <div className="field-action-row">
            <button type="button" className="field-action" data-testid="factory-child-generate-ids" onClick={generateChildIds}>
              <RefreshCw size={12} /> Generate ids
            </button>
          </div>
          <label>Child channel id<input className="mono" data-testid="factory-child-channel-id" value={childChannelId} onChange={event => setChildChannelId(event.target.value)} /></label>
          <label>Counterparty pubkey<input className="mono" data-testid="factory-child-counterparty-pubkey" value={childCounterpartyPubkey} onChange={event => setChildCounterpartyPubkey(event.target.value)} /></label>
          <label>Counterparty alias<input data-testid="factory-child-counterparty-alias" value={childCounterpartyAlias} onChange={event => setChildCounterpartyAlias(event.target.value)} /></label>
          <label>Funding context id<input className="mono" data-testid="factory-child-funding-context-id" value={childFundingContextId} onChange={event => setChildFundingContextId(event.target.value)} /></label>
          <label>Local capacity<input className="mono" data-testid="factory-child-local" value={childLocal} onChange={event => setChildLocal(event.target.value)} /></label>
          <label>Remote capacity<input className="mono" data-testid="factory-child-remote" value={childRemote} onChange={event => setChildRemote(event.target.value)} /></label>
          <label>Pending capacity<input className="mono" data-testid="factory-child-pending" value={childPending} onChange={event => setChildPending(event.target.value)} /></label>
          <label>Sponsor budget<input className="mono" data-testid="factory-child-sponsor-budget" value={childSponsorBudget} onChange={event => setChildSponsorBudget(event.target.value)} /></label>
          <AssetSelect value={childAsset} onChange={setChildAsset} />
          <button data-testid="factory-materialise-child" disabled={busy || orderedFactories.length === 0}><Network size={15} /> Materialise child</button>
        </form>
      </div>
    </div>
  );
}

function StateActions({ state, runAction, busy }: { state: NodeState; runAction: RunAction; busy: boolean }) {
  const [raw, setRaw] = useState('');
  const [stateFileStatus, setStateFileStatus] = useState('');
  const [stateFileBusy, setStateFileBusy] = useState(false);
  const [confirmRestore, setConfirmRestore] = useState(false);

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
        <small>{state.security.state_restore_enabled ? 'Restore is enabled for this API process' : 'Restore is disabled by default'}</small>
      </div>
      <button className="copy-button" data-testid="state-load-json" onClick={exportState} disabled={busy || stateFileBusy}><FileJson size={15} /> Load state JSON</button>
      {stateFileStatus && <small className={stateFileStatus === 'loaded' ? 'inline-ok' : 'inline-error'}>{stateFileStatus}</small>}
      <textarea className="mono" data-testid="state-json" value={raw} onChange={event => setRaw(event.target.value)} />
      <label className="check-row">
        <input
          type="checkbox"
          checked={confirmRestore}
          onChange={event => setConfirmRestore(event.target.checked)}
          disabled={!state.security.state_restore_enabled}
        />
        <span>I understand this replaces the local Hub state file.</span>
      </label>
      <button
        className="danger-button"
        data-testid="state-restore-json"
        onClick={restoreState}
        disabled={busy || !raw.trim() || !state.security.state_restore_enabled || !confirmRestore}
      >
        <Upload size={15} /> Restore state file
      </button>
      {!state.security.state_restore_enabled && (
        <small className="inline-error">Restart with --allow-state-restore to enable this write path.</small>
      )}
    </div>
  );
}

function ChannelSelect({
  channels,
  value,
  onChange,
  label = 'Channel id',
  testId,
}: {
  channels: ChannelRecord[];
  value: string;
  onChange: (value: string) => void;
  label?: string;
  testId: string;
}) {
  return (
    <label>{label}
      <select data-testid={testId} value={value} onChange={event => onChange(event.target.value)}>
        <option value="">select channel</option>
        {channels.map(channel => (
          <option key={channel.channel_id} value={channel.channel_id}>{shortHex(channel.channel_id)} · {channel.phase}</option>
        ))}
      </select>
    </label>
  );
}

function FactorySelect({ factories, value, onChange, testId }: { factories: FactoryRecord[]; value: string; onChange: (value: string) => void; testId: string }) {
  return (
    <label>Factory id
      <select data-testid={testId} value={value} onChange={event => onChange(event.target.value)}>
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
    pending: input.pending.trim() ? assertNonNegativeInteger(input.pending, 'Pending capacity') : undefined,
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

function randomHex32(): Hex32 {
  if (typeof crypto === 'undefined' || !crypto.getRandomValues) {
    throw new Error('Secure browser randomness is unavailable.');
  }
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  if (bytes.every(byte => byte === 0)) {
    bytes[31] = 1;
  }
  return `0x${Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')}` as Hex32;
}

function parsePubkeyDraft(value: string): Pubkey[] {
  return value
    .split(/[\s,]+/)
    .map(item => item.trim().toLowerCase())
    .filter(Boolean);
}

function sortInvoicesNewestFirst(invoices: InvoiceRecord[]): InvoiceRecord[] {
  return [...invoices].sort((left, right) => {
    const byCreatedAt = right.created_at_unix - left.created_at_unix;
    return byCreatedAt || right.invoice_id.localeCompare(left.invoice_id);
  });
}

function newestInvoice(invoices: InvoiceRecord[]): InvoiceRecord | undefined {
  return sortInvoicesNewestFirst(invoices)[0];
}

function sortEventsNewestFirst(events: HubEvent[]): HubEvent[] {
  return [...events].sort((left, right) => {
    const byId = right.id - left.id;
    return byId || right.created_at_unix - left.created_at_unix;
  });
}

function latestEventId(events: HubEvent[]): number {
  return events.reduce((max, event) => Math.max(max, event.id), 0);
}

function sortChannelsForOperator(channels: ChannelRecord[], events: HubEvent[]): ChannelRecord[] {
  const eventRank = subjectEventRank(events);
  return [...channels].sort((left, right) => {
    const byEvent = subjectRank(right.channel_id, eventRank) - subjectRank(left.channel_id, eventRank);
    const byPhase = phaseRank(right.phase) - phaseRank(left.phase);
    const byState = right.state_number - left.state_number;
    const byFunding = right.funding_epoch - left.funding_epoch;
    return byEvent || byPhase || byState || byFunding || right.channel_id.localeCompare(left.channel_id);
  });
}

function sortFactoriesForOperator(factories: FactoryRecord[], events: HubEvent[]): FactoryRecord[] {
  const eventRank = subjectEventRank(events);
  return [...factories].sort((left, right) => {
    const byEvent = subjectRank(right.factory_id, eventRank) - subjectRank(left.factory_id, eventRank);
    const byUpdate = right.update_number - left.update_number;
    const byChildren = right.materialised_child_channels.length - left.materialised_child_channels.length;
    return byEvent || byUpdate || byChildren || right.factory_id.localeCompare(left.factory_id);
  });
}

function sortPeersForOperator(peers: PeerRecord[], events: HubEvent[]): PeerRecord[] {
  const eventRank = subjectEventRank(events);
  return [...peers].sort((left, right) => {
    const byEvent = subjectRank(right.node_id, eventRank) - subjectRank(left.node_id, eventRank);
    const byAlias = left.alias.localeCompare(right.alias);
    return byEvent || byAlias || left.node_id.localeCompare(right.node_id);
  });
}

function subjectEventRank(events: HubEvent[]): Map<string, number> {
  const rank = new Map<string, number>();
  events.forEach(event => {
    if (!event.subject_id) return;
    const subject = event.subject_id.toLowerCase();
    rank.set(subject, Math.max(rank.get(subject) ?? 0, event.id));
  });
  return rank;
}

function subjectRank(subjectId: string, eventRank: Map<string, number>): number {
  return eventRank.get(subjectId.toLowerCase()) ?? 0;
}

function phaseRank(phase: ChannelRecord['phase']): number {
  if (phase === 'active') return 4;
  if (phase === 'settling') return 3;
  if (phase === 'funding') return 2;
  if (phase === 'closed') return 1;
  return 0;
}

async function copyTextToClipboard(text: string): Promise<void> {
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

function liveTone(mode: LiveMode): 'good' | 'neutral' | 'warn' | 'bad' {
  if (mode === 'sse' || mode === 'polling-auth') return 'good';
  if (mode === 'polling') return 'neutral';
  if (mode === 'sse-reconnecting' || mode === 'starting') return 'warn';
  return 'bad';
}

function liveLabel(mode: LiveMode): string {
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

function isAuthTokenError(message: string): boolean {
  return message.toLowerCase().includes('morph hub auth token');
}
