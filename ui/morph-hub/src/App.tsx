import {
  Activity,
  AlertTriangle,
  BadgeCheck,
  Blocks,
  CheckCircle2,
  CircleDollarSign,
  Copy,
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
import { ChangeEvent, FormEvent, useEffect, useMemo, useState } from 'react';
import {
  ChannelRecord,
  FactoryRecord,
  Hex32,
  InvoiceRecord,
  NodeState,
  addAlert,
  completeFlow,
  createInvoice,
  decodeInvoice,
  formatAmount,
  freshState,
  normaliseHex32,
  nowUnix,
  parseState,
  requiredFlows,
  serialiseState,
  shortHex,
  verifyInvoicePreimage,
} from './domain';

type ActionPanel = 'invoice' | 'channel' | 'factory' | 'import';

const storageKey = 'morph-hub-state-v1';
const defaultPreimage = '0x0909090909090909090909090909090909090909090909090909090909090909';
const defaultHex = '0x2222222222222222222222222222222222222222222222222222222222222222';

const navItems: { label: string; Icon: LucideIcon }[] = [
  { label: 'Overview', Icon: Activity },
  { label: 'Channels', Icon: GitBranch },
  { label: 'Invoices', Icon: ReceiptText },
  { label: 'Factories', Icon: Factory },
  { label: 'Watchtower', Icon: RadioTower },
  { label: 'Reports', Icon: FileJson },
];

const actionItems: { key: ActionPanel; Icon: LucideIcon }[] = [
  { key: 'invoice', Icon: ReceiptText },
  { key: 'channel', Icon: GitBranch },
  { key: 'factory', Icon: Factory },
  { key: 'import', Icon: Upload },
];

export function App() {
  const [state, setState] = useState<NodeState>(() => {
    const saved = localStorage.getItem(storageKey);
    return saved ? parseState(saved) : freshState();
  });
  const [activeAction, setActiveAction] = useState<ActionPanel>('invoice');
  const [status, setStatus] = useState('Ready');

  useEffect(() => {
    localStorage.setItem(storageKey, serialiseState(state));
  }, [state]);

  const totals = useMemo(() => {
    const vaultValue = state.channels.reduce(
      (sum, channel) => sum + channel.local + channel.remote + channel.pending,
      0n
    );
    const sponsorBudget = state.channels.reduce((sum, channel) => sum + channel.sponsorBudget, 0n);
    const settlingStates = state.channels.filter(channel => channel.phase === 'settling').length;
    const factoryReserve = state.factories.reduce((sum, factory) => sum + factory.reserve, 0n);
    return { vaultValue, sponsorBudget, settlingStates, factoryReserve };
  }, [state.channels, state.factories]);

  const flowCoverage = Math.round((state.completedFlows.length / requiredFlows.length) * 100);

  const updateState = (next: NodeState, message: string) => {
    setState(next);
    setStatus(message);
  };

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">M</div>
          <div>
            <strong>Morph Hub</strong>
            <span>Cell-native node console</span>
          </div>
        </div>
        <nav className="nav-list">
          {navItems.map(({ label, Icon }) => (
            <button className="nav-item" key={label}>
              <Icon size={17} />
              {label}
            </button>
          ))}
        </nav>
        <div className="coverage">
          <div className="coverage-top">
            <span>Flow coverage</span>
            <strong>{flowCoverage}%</strong>
          </div>
          <div className="meter">
            <span style={{ width: `${flowCoverage}%` }} />
          </div>
          <small>{state.completedFlows.length} of {requiredFlows.length} flows observed</small>
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <h1>Morph Node</h1>
            <p>{shortHex(state.nodeId)} · {state.network}</p>
          </div>
          <div className="topbar-status">
            <StatusPill tone="good" icon={<ShieldCheck size={15} />} label={state.rpcHealth} />
            <StatusPill tone="neutral" icon={<Blocks size={15} />} label={`tip ${state.tipHeight}`} />
            <button
              className="icon-button"
              title="Advance local tip"
              onClick={() => updateState({ ...state, tipHeight: state.tipHeight + 1 }, 'Tip advanced')}
            >
              <RefreshCw size={16} />
            </button>
          </div>
        </header>

        <section className="metric-grid">
          <Metric label="Vault value" value={formatAmount(totals.vaultValue, { kind: 'ckb' })} icon={<Landmark />} />
          <Metric label="Sponsor budget" value={formatAmount(totals.sponsorBudget, { kind: 'ckb' })} icon={<WalletCards />} />
          <Metric label="Settling states" value={String(totals.settlingStates)} icon={<AlertTriangle />} tone={totals.settlingStates ? 'warn' : 'base'} />
          <Metric label="Factory reserve" value={formatAmount(totals.factoryReserve, { kind: 'ckb' })} icon={<Factory />} />
        </section>

        <section className="flow-panel">
          <div className="section-head">
            <h2>Business Flow</h2>
            <span>{status}</span>
          </div>
          <div className="flow-line">
            {['Open', 'Update', 'Publish', 'Finalise'].map((step, index) => (
              <div className="flow-step" key={step}>
                <span>{index + 1}</span>
                <strong>{step}</strong>
              </div>
            ))}
            <div className="flow-branch"><Split size={18} /> Splice / resize</div>
          </div>
        </section>

        <section className="content-grid">
          <ChannelTable
            channels={state.channels}
            onSplice={channelId => {
              const next = state.channels.map(channel =>
                channel.channelId === channelId
                  ? {
                      ...channel,
                      fundingEpoch: channel.fundingEpoch + 1,
                      fundingContextId: randomHex32(),
                    }
                  : channel
              );
              updateState(
                addAlert(completeFlow({ ...state, channels: next }, 'channel-spliced'), {
                  severity: 'info',
                  event: 'splice_detected',
                  channelId,
                  message: 'Funding context advanced',
                }),
                'Channel spliced'
              );
            }}
            onPublish={channelId => {
              const next = state.channels.map(channel =>
                channel.channelId === channelId
                  ? { ...channel, phase: 'settling' as const, stateNumber: channel.stateNumber + 1 }
                  : channel
              );
              updateState(
                addAlert(completeFlow({ ...state, channels: next }, 'state-published'), {
                  severity: 'warning',
                  event: 'publication_submitted',
                  channelId,
                  message: 'Latest state published',
                }),
                'State published'
              );
            }}
            onFinalise={channelId => {
              const next = state.channels.map(channel =>
                channel.channelId === channelId && channel.phase === 'settling'
                  ? { ...channel, phase: 'closed' as const }
                  : channel
              );
              updateState(completeFlow({ ...state, channels: next }, 'channel-finalised'), 'Channel finalised');
            }}
          />

          <InvoicePanel
            invoices={state.invoices}
            onReceive={invoiceId => {
              updateState(
                completeFlow(
                  {
                    ...state,
                    invoices: state.invoices.map(invoice =>
                      invoice.invoiceId === invoiceId ? { ...invoice, status: 'received' } : invoice
                    ),
                  },
                  'invoice-received'
                ),
                'Invoice marked received'
              );
            }}
          />

          <FactoryPanel factories={state.factories} />
          <WatchtowerPanel alerts={state.watchtowerAlerts} />
        </section>
      </section>

      <aside className="action-drawer">
        <div className="drawer-tabs">
          {actionItems.map(({ key, Icon }) => (
            <button
              className={activeAction === key ? 'selected' : ''}
              key={key}
              onClick={() => setActiveAction(key)}
              title={key}
            >
              <Icon size={16} />
            </button>
          ))}
        </div>
        {activeAction === 'invoice' && <InvoiceActions state={state} updateState={updateState} />}
        {activeAction === 'channel' && <ChannelActions state={state} updateState={updateState} />}
        {activeAction === 'factory' && <FactoryActions state={state} updateState={updateState} />}
        {activeAction === 'import' && <ImportActions state={state} updateState={updateState} />}
      </aside>
    </main>
  );
}

function StatusPill({ icon, label, tone }: { icon: React.ReactNode; label: string; tone: 'good' | 'neutral' }) {
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

function ChannelTable({
  channels,
  onSplice,
  onPublish,
  onFinalise,
}: {
  channels: ChannelRecord[];
  onSplice: (channelId: Hex32) => void;
  onPublish: (channelId: Hex32) => void;
  onFinalise: (channelId: Hex32) => void;
}) {
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
            <th>Funding context</th>
            <th>Sponsor</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {channels.length === 0 && (
            <tr><td colSpan={6} className="empty">No channels loaded</td></tr>
          )}
          {channels.map(channel => (
            <tr key={channel.channelId}>
              <td><strong>{shortHex(channel.channelId)}</strong><small>{channel.counterparty}</small></td>
              <td><span className={`phase ${channel.phase}`}>{channel.phase}</span></td>
              <td>{channel.stateNumber}</td>
              <td>{shortHex(channel.fundingContextId)}</td>
              <td>{formatAmount(channel.sponsorBudget, { kind: 'ckb' })}</td>
              <td className="row-actions">
                <button title="Splice" onClick={() => onSplice(channel.channelId)}><Split size={14} /></button>
                <button title="Publish" onClick={() => onPublish(channel.channelId)}><RadioTower size={14} /></button>
                <button title="Finalise" onClick={() => onFinalise(channel.channelId)}><CheckCircle2 size={14} /></button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

function InvoicePanel({ invoices, onReceive }: { invoices: InvoiceRecord[]; onReceive: (invoiceId: Hex32) => void }) {
  return (
    <section className="panel">
      <div className="section-head">
        <h2>Invoices</h2>
        <span>{invoices.filter(invoice => invoice.status === 'open').length} open</span>
      </div>
      <div className="stack-list">
        {invoices.length === 0 && <div className="empty">No invoices loaded</div>}
        {invoices.slice(0, 5).map(invoice => (
          <div className="list-row" key={invoice.invoiceId}>
            <div>
              <strong>{invoice.description || shortHex(invoice.invoiceId)}</strong>
              <small>{formatAmount(invoice.amount, invoice.asset)} · {shortHex(invoice.paymentHash)}</small>
            </div>
            <button className={`status ${invoice.status}`} onClick={() => onReceive(invoice.invoiceId)}>
              {invoice.status}
            </button>
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
        {factories.length === 0 && <div className="empty">No factories loaded</div>}
        {factories.map(factory => (
          <div className="list-row" key={factory.factoryId}>
            <div>
              <strong>{shortHex(factory.factoryId)}</strong>
              <small>update {factory.updateNumber} · {factory.materialisedChildren.length} children</small>
            </div>
            <span className="amount">{formatAmount(factory.reserve, factory.asset)}</span>
          </div>
        ))}
      </div>
    </section>
  );
}

function WatchtowerPanel({ alerts }: { alerts: NodeState['watchtowerAlerts'] }) {
  return (
    <section className="panel">
      <div className="section-head">
        <h2>Watchtower</h2>
        <span>{alerts.length} alerts</span>
      </div>
      <div className="alert-strip">
        {alerts.length === 0 && <div className="empty">No watchtower alerts</div>}
        {alerts.map(alert => (
          <div className={`alert ${alert.severity}`} key={alert.id}>
            <AlertTriangle size={15} />
            <div>
              <strong>{alert.event}</strong>
              <small>{alert.message}</small>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

function InvoiceActions({ state, updateState }: { state: NodeState; updateState: (state: NodeState, message: string) => void }) {
  const [amount, setAmount] = useState('100000000');
  const [description, setDescription] = useState('Morph channel payment');
  const [preimage, setPreimage] = useState<Hex32>(defaultPreimage);
  const [decodeText, setDecodeText] = useState('');
  const [settlePreimage, setSettlePreimage] = useState<Hex32>(defaultPreimage);
  const [error, setError] = useState('');

  const submitCreate = (event: FormEvent) => {
    event.preventDefault();
    setError('');
    try {
      const invoice = createInvoice({
        state,
        amount: BigInt(amount),
        description,
        preimage: normaliseHex32(preimage),
        expirySecs: 3600,
      });
      updateState(completeFlow({ ...state, invoices: [invoice, ...state.invoices] }, 'invoice-created'), 'Invoice created');
    } catch (err) {
      setError(String((err as Error).message));
    }
  };

  const submitDecode = (event: FormEvent) => {
    event.preventDefault();
    setError('');
    try {
      const invoice = decodeInvoice(decodeText.trim());
      updateState(completeFlow({ ...state, invoices: [invoice, ...state.invoices] }, 'invoice-received'), 'Invoice decoded');
    } catch (err) {
      setError(String((err as Error).message));
    }
  };

  const settleLatest = () => {
    setError('');
    const invoice = state.invoices.find(item => item.status === 'open' || item.status === 'received');
    if (!invoice) {
      setError('No open invoice available.');
      return;
    }
    try {
      const preimageHex = normaliseHex32(settlePreimage);
      if (!verifyInvoicePreimage(invoice, preimageHex)) throw new Error('Preimage does not match invoice.');
      updateState(
        completeFlow(
          {
            ...state,
            invoices: state.invoices.map(item =>
              item.invoiceId === invoice.invoiceId ? { ...item, status: 'paid' } : item
            ),
          },
          'invoice-settled'
        ),
        'Invoice settled'
      );
    } catch (err) {
      setError(String((err as Error).message));
    }
  };

  return (
    <div className="drawer-section">
      <h2>Invoice Layer</h2>
      <form onSubmit={submitCreate} className="form-grid">
        <label>Amount<input value={amount} onChange={event => setAmount(event.target.value)} /></label>
        <label>Description<input value={description} onChange={event => setDescription(event.target.value)} /></label>
        <label>Preimage<input value={preimage} onChange={event => setPreimage(event.target.value as Hex32)} /></label>
        <button><Plus size={15} /> Create</button>
      </form>
      <form onSubmit={submitDecode} className="form-grid">
        <label>Encoded invoice<textarea value={decodeText} onChange={event => setDecodeText(event.target.value)} /></label>
        <button><ReceiptText size={15} /> Decode</button>
      </form>
      <div className="form-grid">
        <label>Settlement preimage<input value={settlePreimage} onChange={event => setSettlePreimage(event.target.value as Hex32)} /></label>
        <button onClick={settleLatest}><BadgeCheck size={15} /> Settle latest</button>
      </div>
      {state.invoices[0] && (
        <button className="copy-button" onClick={() => navigator.clipboard.writeText(state.invoices[0].encodedInvoice)}>
          <Copy size={15} /> Copy latest invoice
        </button>
      )}
      {error && <div className="error">{error}</div>}
    </div>
  );
}

function ChannelActions({ state, updateState }: { state: NodeState; updateState: (state: NodeState, message: string) => void }) {
  const [counterparty, setCounterparty] = useState('bob');
  const [local, setLocal] = useState('1000000000');
  const [remote, setRemote] = useState('500000000');
  const [sponsor, setSponsor] = useState('5000000000');

  const submit = (event: FormEvent) => {
    event.preventDefault();
    const channel: ChannelRecord = {
      channelId: randomHex32(),
      counterparty,
      phase: 'active',
      stateNumber: 1,
      fundingEpoch: 0,
      fundingContextId: randomHex32(),
      local: BigInt(local),
      remote: BigInt(remote),
      pending: 0n,
      sponsorBudget: BigInt(sponsor),
      asset: { kind: 'ckb' },
    };
    const next = completeFlow(
      completeFlow({ ...state, peers: state.peers.includes(counterparty) ? state.peers : [...state.peers, counterparty], channels: [channel, ...state.channels] }, 'peer'),
      'channel-opened'
    );
    updateState(next, 'Channel opened');
  };

  return (
    <div className="drawer-section">
      <h2>Node Layer</h2>
      <form onSubmit={submit} className="form-grid">
        <label>Counterparty<input value={counterparty} onChange={event => setCounterparty(event.target.value)} /></label>
        <label>Local capacity<input value={local} onChange={event => setLocal(event.target.value)} /></label>
        <label>Remote capacity<input value={remote} onChange={event => setRemote(event.target.value)} /></label>
        <label>Sponsor budget<input value={sponsor} onChange={event => setSponsor(event.target.value)} /></label>
        <button><GitBranch size={15} /> Open channel</button>
      </form>
    </div>
  );
}

function FactoryActions({ state, updateState }: { state: NodeState; updateState: (state: NodeState, message: string) => void }) {
  const [reserve, setReserve] = useState('10000000000');
  const [participants, setParticipants] = useState('alice,bob');

  const openFactory = () => {
    const factory: FactoryRecord = {
      factoryId: randomHex32(),
      updateNumber: 0,
      reserve: BigInt(reserve),
      asset: { kind: 'ckb' },
      participants: participants.split(',').map(value => value.trim()).filter(Boolean),
      materialisedChildren: [],
    };
    updateState(completeFlow({ ...state, factories: [factory, ...state.factories] }, 'factory-opened'), 'Factory opened');
  };

  const advanceFactory = () => {
    const first = state.factories[0];
    if (!first) return;
    updateState(
      completeFlow(
        { ...state, factories: state.factories.map(factory => factory.factoryId === first.factoryId ? { ...factory, updateNumber: factory.updateNumber + 1 } : factory) },
        'factory-advanced'
      ),
      'Factory advanced'
    );
  };

  const materialise = () => {
    const first = state.factories[0];
    if (!first) return;
    const child = randomHex32();
    updateState(
      completeFlow(
        { ...state, factories: state.factories.map(factory => factory.factoryId === first.factoryId ? { ...factory, materialisedChildren: [child, ...factory.materialisedChildren] } : factory) },
        'factory-child'
      ),
      'Child channel materialised'
    );
  };

  return (
    <div className="drawer-section">
      <h2>Factory Layer</h2>
      <div className="form-grid">
        <label>Reserve<input value={reserve} onChange={event => setReserve(event.target.value)} /></label>
        <label>Participants<input value={participants} onChange={event => setParticipants(event.target.value)} /></label>
        <button onClick={openFactory}><Factory size={15} /> Open factory</button>
        <button onClick={advanceFactory}><RefreshCw size={15} /> Advance latest</button>
        <button onClick={materialise}><Network size={15} /> Materialise child</button>
      </div>
    </div>
  );
}

function ImportActions({ state, updateState }: { state: NodeState; updateState: (state: NodeState, message: string) => void }) {
  const [raw, setRaw] = useState(serialiseState(state));
  const [error, setError] = useState('');

  const loadFile = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    file.text().then(setRaw).catch(err => setError(String(err)));
  };

  const importState = () => {
    try {
      updateState(parseState(raw), 'Snapshot imported');
      setError('');
    } catch (err) {
      setError(String((err as Error).message));
    }
  };

  const exportState = () => {
    const blob = new Blob([serialiseState(state)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'morph-node-snapshot.json';
    anchor.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="drawer-section">
      <h2>Snapshot</h2>
      <input type="file" accept="application/json" onChange={loadFile} />
      <textarea className="snapshot" value={raw} onChange={event => setRaw(event.target.value)} />
      <button onClick={importState}><Upload size={15} /> Import</button>
      <button onClick={exportState}><FileJson size={15} /> Export current</button>
      {error && <div className="error">{error}</div>}
    </div>
  );
}

function randomHex32(): Hex32 {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return `0x${[...bytes].map(byte => byte.toString(16).padStart(2, '0')).join('')}`;
}
