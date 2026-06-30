import { Activity, BadgeCheck, Factory, FileJson, GitBranch, Network, Plus, RadioTower, ReceiptText, RefreshCw, Split, Upload, Users } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import type React from 'react';
import { FormEvent, useEffect, useState } from 'react';
import { connectPeer, getStateFile, postAction, replaceStateFile } from './api';
import {
  Asset,
  ChannelRecord,
  FactoryRecord,
  Hex32,
  HubEvent,
  InvoiceRecord,
  NodeState,
  PeerRecord,
  Pubkey,
  assertHex32,
  assertIncludesPubkey,
  assertInvoiceAmount,
  assertNonNegativeInteger,
  assertPositiveInteger,
  assertRemotePubkey,
  assetLabel,
  formatAmount,
  normaliseAsset,
  parsePubkeyList,
  shortHex,
} from './domain';

type RunAction = (label: string, action: () => Promise<NodeState>) => Promise<void>;
type ChannelActionTab = 'open' | 'splice' | 'publish' | 'finalise';
type FactoryActionTab = 'open' | 'advance' | 'materialise';
type FactoryActionTarget = {
  factoryId: Hex32;
  intent: 'advance' | 'materialise';
  nonce: number;
};
type ChannelFormMode = 'open' | 'materialise';
type ChannelFormDraft = {
  channelId: string;
  counterpartyPubkey: string;
  counterpartyAlias: string;
  fundingContextId: string;
  local: string;
  remote: string;
  pending: string;
  sponsorBudget: string;
  asset: Asset;
};
type ChannelFormPrefill = {
  nonce: number;
  draft: Partial<ChannelFormDraft>;
};

const DEFAULT_INVOICE_EXPIRY_SECS = '3600';
const DEFAULT_PENDING_CAPACITY = '0';
const DEFAULT_SPONSOR_BUDGET = '1000000';
const MAX_PEER_ALIAS_LEN = 80;

const invoiceExpiryPresets = [
  { label: '1h', value: '3600' },
  { label: '6h', value: '21600' },
  { label: '24h', value: '86400' },
  { label: '7d', value: '604800' },
];

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

export function PeerActions({ state, runAction, busy }: { state: NodeState; runAction: RunAction; busy: boolean }) {
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
        <ValidatedInput label="Peer pubkey" className="mono" testId="peer-pubkey" value={pubkey} onChange={setPubkey} validate={value => { assertRemotePubkey(value, state.pubkey, 'Peer pubkey'); }} />
        <ValidatedInput label="Alias" testId="peer-alias" value={alias} onChange={setAlias} maxLength={MAX_PEER_ALIAS_LEN} validate={value => { requiredText(value, 'Alias'); }} />
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
        <ValidatedInput label="Type hash" className="mono" value={typeHash} onChange={updateHash} validate={value => { assertHex32(value, 'Type hash'); }} />
      )}
    </>
  );
}

export function InvoiceActions({ state, runAction, busy }: { state: NodeState; runAction: RunAction; busy: boolean }) {
  const [amount, setAmount] = useState('');
  const [description, setDescription] = useState('');
  const [expirySecs, setExpirySecs] = useState(DEFAULT_INVOICE_EXPIRY_SECS);
  const [paymentMode, setPaymentMode] = useState<'preimage' | 'hash'>('preimage');
  const [paymentSecret, setPaymentSecret] = useState(createDraftHex32);
  const [channelId, setChannelId] = useState('');
  const [asset, setAsset] = useState<Asset>({ kind: 'ckb' });
  const [decodeText, setDecodeText] = useState('');
  const [settleInvoiceId, setSettleInvoiceId] = useState('');
  const [settlePreimage, setSettlePreimage] = useState('');
  const [copyStatus, setCopyStatus] = useState('');
  const activeChannels = sortChannelsForOperator(state.channels, state.events).filter(channel => channel.phase === 'active');
  const latestActiveChannel = activeChannels[0];
  const canCreateInvoices = state.security.invoice_signing_enabled;
  const settleableInvoices = sortInvoicesNewestFirst(state.invoices.filter(invoice => invoice.status === 'open' || invoice.status === 'received'));
  const latestSettleableInvoice = newestInvoice(
    settleableInvoices
  );

  useEffect(() => {
    if (!channelId && latestActiveChannel) {
      setChannelId(latestActiveChannel.channel_id);
    }
  }, [channelId, latestActiveChannel]);

  useEffect(() => {
    if (paymentMode === 'preimage' && !paymentSecret) {
      setPaymentSecret(createDraftHex32());
    }
  }, [paymentMode, paymentSecret]);

  useEffect(() => {
    if (!settleInvoiceId && latestSettleableInvoice) {
      setSettleInvoiceId(latestSettleableInvoice.invoice_id);
    }
  }, [settleInvoiceId, latestSettleableInvoice]);

  const submitCreate = (event: FormEvent) => {
    event.preventDefault();
    void runAction('Create invoice', async () => {
      const body = {
        amount: assertInvoiceAmount(amount, asset),
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
    const encodedInvoice = requiredText(decodeText, 'Encoded invoice');
    void runAction('Receive invoice', async () => {
      const previousInvoiceIds = new Set(state.invoices.map(invoice => invoice.invoice_id));
      const decodedState = await postAction('/api/invoices/decode', { encoded_invoice: encodedInvoice });
      const decodedInvoice = newestInvoice(decodedState.invoices.filter(invoice => !previousInvoiceIds.has(invoice.invoice_id) || invoice.encoded_invoice === encodedInvoice));
      if (decodedInvoice?.status === 'open') {
        return postAction(`/api/invoices/${decodedInvoice.invoice_id}/receive`);
      }
      return decodedState;
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
        <ValidatedInput label="Amount" className="mono" testId="invoice-amount" value={amount} onChange={setAmount} validate={value => { assertInvoiceAmount(value, asset); }} />
        <label>Description<input data-testid="invoice-description" value={description} onChange={event => setDescription(event.target.value)} /></label>
        <ValidatedInput
          label={(
            <span className="field-label-row">
            Expiry seconds
              <span className="quick-picks">
                {invoiceExpiryPresets.map(preset => (
                  <button type="button" className="field-action" key={preset.value} onClick={() => setExpirySecs(preset.value)}>
                    {preset.label}
                  </button>
                ))}
              </span>
            </span>
          )}
          className="mono"
          testId="invoice-expiry-secs"
          value={expirySecs}
          onChange={setExpirySecs}
          validate={value => { assertPositiveInteger(value, 'Expiry seconds'); }}
        />
        <label>Payment input
          <select data-testid="invoice-payment-mode" value={paymentMode} onChange={event => setPaymentMode(event.target.value as 'preimage' | 'hash')}>
            <option value="preimage">preimage</option>
            <option value="hash">hash</option>
          </select>
        </label>
        <ValidatedInput
          label={(
            <span className="field-label-row">
              {paymentMode === 'preimage' ? 'Payment preimage' : 'Payment hash'}
              {paymentMode === 'preimage' && (
                <button type="button" className="field-action" data-testid="invoice-generate-payment-secret" onClick={() => setPaymentSecret(randomHex32())}>
                  <RefreshCw size={12} /> Generate
                </button>
              )}
            </span>
          )}
          className="mono"
          testId="invoice-payment-secret"
          value={paymentSecret}
          onChange={setPaymentSecret}
          validate={value => { assertHex32(value, paymentMode === 'preimage' ? 'Payment preimage' : 'Payment hash'); }}
        />
        <ValidatedInput
          label={(
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
          )}
          className="mono"
          testId="invoice-channel-id"
          value={channelId}
          onChange={setChannelId}
          validate={value => { if (value.trim()) assertHex32(value, 'Channel id'); }}
        />
        <AssetSelect value={asset} onChange={setAsset} />
        <button data-testid="invoice-create" disabled={busy || !canCreateInvoices}><Plus size={15} /> Create invoice</button>
        {!canCreateInvoices && (
          <small className="inline-error">Restart Hub with MORPH_HUB_INVOICE_PRIVATE_KEY or --invoice-private-key to create signed invoices.</small>
        )}
      </form>

      <div className="form-section">
        <h3>Receive from text</h3>
        <form onSubmit={submitDecode} className="form-grid">
          <label>Encoded invoice<textarea className="mono" data-testid="invoice-decode-text" value={decodeText} onChange={event => setDecodeText(event.target.value)} /></label>
          <button data-testid="invoice-decode" disabled={busy}><ReceiptText size={15} /> Receive invoice</button>
        </form>
      </div>

      <div className="form-section">
        <h3>Settle</h3>
        <form onSubmit={submitSettle} className="form-grid">
          <label>Invoice
            <select data-testid="invoice-settle-id" value={settleInvoiceId} onChange={event => setSettleInvoiceId(event.target.value)}>
              <option value="">select invoice</option>
              {settleableInvoices.map(invoice => (
                <option key={invoice.invoice_id} value={invoice.invoice_id}>{shortHex(invoice.invoice_id)} · {invoice.status} · {invoice.description || formatAmount(invoice.amount, invoice.asset)}</option>
              ))}
            </select>
          </label>
          <ValidatedInput label="Payment preimage" className="mono" testId="invoice-settle-preimage" value={settlePreimage} onChange={setSettlePreimage} validate={value => { assertHex32(value, 'Payment preimage'); }} />
          <button data-testid="invoice-settle" disabled={busy || !settleInvoiceId}><BadgeCheck size={15} /> Settle</button>
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

function ActionSubTabs<T extends string>({
  items,
  active,
  onChange,
}: {
  items: { key: T; label: string; Icon: LucideIcon; disabled?: boolean }[];
  active: T;
  onChange: (key: T) => void;
}) {
  return (
    <div className="action-sub-tabs">
      {items.map(({ key, label, Icon, disabled }) => (
        <button
          key={key}
          type="button"
          className={active === key ? 'selected' : ''}
          onClick={() => onChange(key)}
          disabled={disabled}
        >
          <Icon size={14} />
          <span>{label}</span>
        </button>
      ))}
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
        className={`${className ?? ''} ${error ? 'invalid' : ''}`.trim()}
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

function ValidatedTextarea({
  label,
  value,
  onChange,
  validate,
  testId,
  className,
}: {
  label: React.ReactNode;
  value: string;
  onChange: (value: string) => void;
  validate: (value: string) => void;
  testId?: string;
  className?: string;
}) {
  const [touched, setTouched] = useState(false);
  const error = touched ? validationError(value, validate) : '';
  return (
    <label>
      {label}
      <textarea
        className={`${className ?? ''} ${error ? 'invalid' : ''}`.trim()}
        data-testid={testId}
        value={value}
        onBlur={() => setTouched(true)}
        onChange={event => onChange(event.target.value)}
      />
      {error && <small className="field-error">{error}</small>}
    </label>
  );
}

export function ChannelActions({ state, runAction, busy }: { state: NodeState; runAction: RunAction; busy: boolean }) {
  const [activeTab, setActiveTab] = useState<ChannelActionTab>('open');
  const [spliceChannelId, setSpliceChannelId] = useState('');
  const [publishChannelId, setPublishChannelId] = useState('');
  const [finaliseChannelId, setFinaliseChannelId] = useState('');
  const [pendingFinaliseChannel, setPendingFinaliseChannel] = useState<ChannelRecord | null>(null);
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
  const selectedFinaliseChannel = settlingChannels.find(channel => channel.channel_id === finaliseChannelId);

  const submitSplice = (event: FormEvent) => {
    event.preventDefault();
    void runAction('Record splice', () => {
      const id = assertHex32(spliceChannelId, 'Channel id');
      return postAction(`/api/channels/${id}/splice`, {
        new_funding_epoch: Number(assertPositiveInteger(spliceEpoch, 'New funding epoch')),
        new_funding_context_id: assertHex32(spliceContextId, 'New funding context id'),
      });
    });
  };

  const submitPublish = (event: FormEvent) => {
    event.preventDefault();
    void runAction('Update tracked state', () => {
      const id = assertHex32(publishChannelId, 'Channel id');
      return postAction(`/api/channels/${id}/publish`, {
        funding_context_id: assertHex32(publishContextId, 'Funding context id'),
        state_number: Number(assertPositiveInteger(publishStateNumber, 'State number')),
      });
    });
  };

  const submitFinalise = (event: FormEvent) => {
    event.preventDefault();
    if (selectedFinaliseChannel) setPendingFinaliseChannel(selectedFinaliseChannel);
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
      <p className="inline-note">Hub channel controls update local off-chain records; they do not build or broadcast CKB transactions.</p>
      <ActionSubTabs<ChannelActionTab>
        active={activeTab}
        onChange={setActiveTab}
        items={[
          { key: 'open', label: 'Open', Icon: GitBranch },
          { key: 'splice', label: 'Splice', Icon: Split, disabled: activeChannels.length === 0 },
          { key: 'publish', label: 'Update', Icon: RadioTower, disabled: publishableChannels.length === 0 },
          { key: 'finalise', label: 'Finalise', Icon: BadgeCheck, disabled: settlingChannels.length === 0 },
        ]}
      />
      {activeTab === 'open' && (
        <ChannelOpenForm
          mode="open"
          state={state}
          runAction={runAction}
          busy={busy}
          actionLabel="Open channel"
          submitLabel="Open channel"
          submitTestId="channel-open"
          testPrefix="channel"
          submitIcon={<GitBranch size={15} />}
          onSubmit={body => postAction('/api/channels', body)}
        />
      )}

      {activeTab === 'splice' && <div className="form-section">
        <h3>Record splice</h3>
        <form onSubmit={submitSplice} className="form-grid">
          <ChannelSelect testId="channel-splice-select" label="Active channel" channels={activeChannels} value={spliceChannelId} onChange={setSpliceChannelId} />
          <div className="field-action-row">
            <button type="button" className="field-action" data-testid="channel-splice-use-selected" onClick={useSelectedSpliceDefaults} disabled={!selectedSpliceChannel}>
              <RefreshCw size={12} /> Use selected
            </button>
          </div>
          <ValidatedInput label="New funding epoch" className="mono" testId="channel-splice-epoch" value={spliceEpoch} onChange={setSpliceEpoch} validate={value => { assertPositiveInteger(value, 'New funding epoch'); }} />
          <ValidatedInput label="New funding context id" className="mono" testId="channel-splice-context-id" value={spliceContextId} onChange={setSpliceContextId} validate={value => { assertHex32(value, 'New funding context id'); }} />
          <button data-testid="channel-splice" disabled={busy || activeChannels.length === 0}><Split size={15} /> Record splice</button>
        </form>
      </div>}

      {activeTab === 'publish' && <div className="form-section">
        <h3>Update tracked state</h3>
        <form onSubmit={submitPublish} className="form-grid">
          <ChannelSelect testId="channel-publish-select" label="Trackable channel" channels={publishableChannels} value={publishChannelId} onChange={setPublishChannelId} />
          <div className="field-action-row">
            <button type="button" className="field-action" data-testid="channel-publish-use-selected" onClick={useSelectedPublishDefaults} disabled={!selectedPublishChannel}>
              <Activity size={12} /> Use selected
            </button>
          </div>
          <ValidatedInput label="Funding context id" className="mono" testId="channel-publish-context-id" value={publishContextId} onChange={setPublishContextId} validate={value => { assertHex32(value, 'Funding context id'); }} />
          <ValidatedInput label="State number" className="mono" testId="channel-publish-state-number" value={publishStateNumber} onChange={setPublishStateNumber} validate={value => { assertPositiveInteger(value, 'State number'); }} />
          <button data-testid="channel-publish" disabled={busy || publishableChannels.length === 0}><RadioTower size={15} /> Update state</button>
        </form>
      </div>}

      {activeTab === 'finalise' && <div className="form-section">
        <h3>Finalise</h3>
        <form onSubmit={submitFinalise} className="form-grid">
          <ChannelSelect testId="channel-finalise-select" label="Settling channel" channels={settlingChannels} value={finaliseChannelId} onChange={setFinaliseChannelId} />
          <button data-testid="channel-finalise" disabled={busy || !selectedFinaliseChannel}><BadgeCheck size={15} /> Finalise channel</button>
        </form>
      </div>}
      {pendingFinaliseChannel && (
        <ConfirmActionDialog
          title={`Finalise channel ${shortHex(pendingFinaliseChannel.channel_id)}?`}
          detail={`This closes the settling channel at state ${pendingFinaliseChannel.state_number}. It cannot be undone from this console.`}
          confirmLabel="Finalise"
          busy={busy}
          onCancel={() => setPendingFinaliseChannel(null)}
          onConfirm={() => {
            const id = pendingFinaliseChannel.channel_id;
            void runAction('Finalise channel', () => postAction(`/api/channels/${id}/finalise`)).then(() => setPendingFinaliseChannel(null));
          }}
        />
      )}
    </div>
  );
}

export function FactoryActions({
  state,
  runAction,
  busy,
  target,
}: {
  state: NodeState;
  runAction: RunAction;
  busy: boolean;
  target: FactoryActionTarget | null;
}) {
  const [activeTab, setActiveTab] = useState<FactoryActionTab>('open');
  const [factoryId, setFactoryId] = useState(createDraftHex32);
  const [selectedParticipantPubkeys, setSelectedParticipantPubkeys] = useState<string[]>([]);
  const [customParticipantPubkeys, setCustomParticipantPubkeys] = useState('');
  const [reserve, setReserve] = useState('');
  const [factoryAsset, setFactoryAsset] = useState<Asset>({ kind: 'ckb' });
  const [selectedFactoryId, setSelectedFactoryId] = useState('');
  const [newUpdateNumber, setNewUpdateNumber] = useState('');
  const [materialisePrefill, setMaterialisePrefill] = useState<ChannelFormPrefill | null>(null);
  const orderedFactories = sortFactoriesForOperator(state.factories, state.events);
  const selectedFactory = orderedFactories.find(factory => factory.factory_id === selectedFactoryId);

  useEffect(() => {
    if (!target) return;
    const targetFactory = orderedFactories.find(factory => factory.factory_id === target.factoryId);
    setSelectedFactoryId(target.factoryId);
    if (target.intent === 'advance') {
      setActiveTab('advance');
      setNewUpdateNumber(targetFactory ? String(targetFactory.update_number + 1) : '');
      return;
    }
    setActiveTab('materialise');
    setMaterialisePrefill({
      nonce: target.nonce,
      draft: {
        channelId: createDraftHex32(),
        fundingContextId: createDraftHex32(),
        pending: DEFAULT_PENDING_CAPACITY,
        sponsorBudget: DEFAULT_SPONSOR_BUDGET,
        asset: targetFactory?.reserve_balances[0]?.asset ?? { kind: 'ckb' },
      },
    });
  }, [target?.nonce]);

  const submitOpen = (event: FormEvent) => {
    event.preventDefault();
    void runAction('Open factory', () => {
      const customPubkeys = customParticipantPubkeys.trim()
        ? parsePubkeyList(customParticipantPubkeys, 'Custom participant pubkeys')
        : [];
      const participant_pubkeys = uniqueStrings([
        state.pubkey,
        ...selectedParticipantPubkeys,
        ...customPubkeys,
      ]);
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

  const toggleParticipant = (pubkey: string) => {
    setSelectedParticipantPubkeys(current => (
      current.includes(pubkey)
        ? current.filter(item => item !== pubkey)
        : [...current, pubkey]
    ));
  };

  const generateFactoryId = () => {
    setFactoryId(randomHex32());
  };

  const useSelectedFactoryUpdate = () => {
    if (!selectedFactory) return;
    setNewUpdateNumber(String(selectedFactory.update_number + 1));
  };

  return (
    <div className="drawer-section">
      <h2>Factory Layer</h2>
      <ActionSubTabs<FactoryActionTab>
        active={activeTab}
        onChange={setActiveTab}
        items={[
          { key: 'open', label: 'Open', Icon: Factory },
          { key: 'advance', label: 'Advance', Icon: RefreshCw, disabled: orderedFactories.length === 0 },
          { key: 'materialise', label: 'Child', Icon: Network, disabled: orderedFactories.length === 0 },
        ]}
      />
      {activeTab === 'open' && <form onSubmit={submitOpen} className="form-grid">
        <ValidatedInput
          label={(
            <span className="field-label-row">
              Factory id
              <button type="button" className="field-action" data-testid="factory-generate-id" onClick={generateFactoryId}>
                <RefreshCw size={12} /> Generate
              </button>
            </span>
          )}
          className="mono"
          testId="factory-id"
          value={factoryId}
          onChange={setFactoryId}
          validate={value => { assertHex32(value, 'Factory id'); }}
        />
        <label>
          Participants
          <div className="participant-picker" data-testid="factory-participants">
            <span className="participant-chip selected" title={state.pubkey}>
              Local {shortHex(state.pubkey)}
            </span>
            {state.peers.map(peer => {
              const selected = selectedParticipantPubkeys.includes(peer.pubkey);
              return (
                <button
                  type="button"
                  className={`participant-chip ${selected ? 'selected' : ''}`}
                  key={peer.pubkey}
                  onClick={() => toggleParticipant(peer.pubkey)}
                  title={peer.pubkey}
                >
                  {selected ? <BadgeCheck size={12} /> : <Plus size={12} />}
                  {peer.alias || shortHex(peer.pubkey)}
                </button>
              );
            })}
            {state.peers.length === 0 && <small>No connected peers yet</small>}
          </div>
        </label>
        <ValidatedTextarea
          label="Custom participant pubkeys"
          className="mono compact"
          testId="factory-participants-custom"
          value={customParticipantPubkeys}
          onChange={setCustomParticipantPubkeys}
          validate={value => { if (value.trim()) parsePubkeyList(value, 'Custom participant pubkeys'); }}
        />
        <ValidatedInput label="Reserve" className="mono" testId="factory-reserve" value={reserve} onChange={setReserve} validate={value => { assertPositiveInteger(value, 'Reserve'); }} />
        <AssetSelect value={factoryAsset} onChange={setFactoryAsset} />
        <button data-testid="factory-open" disabled={busy}><Factory size={15} /> Open factory</button>
      </form>}

      {activeTab === 'advance' && <div className="form-section">
        <h3>Advance</h3>
        <form onSubmit={submitAdvance} className="form-grid">
          <FactorySelect testId="factory-advance-select" factories={orderedFactories} value={selectedFactoryId} onChange={setSelectedFactoryId} />
          <div className="field-action-row">
            <button type="button" className="field-action" data-testid="factory-advance-use-selected" onClick={useSelectedFactoryUpdate} disabled={!selectedFactory}>
              <Activity size={12} /> Use selected
            </button>
          </div>
          <ValidatedInput label="New update number" className="mono" testId="factory-new-update-number" value={newUpdateNumber} onChange={setNewUpdateNumber} validate={value => { assertPositiveInteger(value, 'New update number'); }} />
          <button data-testid="factory-advance" disabled={busy || orderedFactories.length === 0}><RefreshCw size={15} /> Advance</button>
        </form>
      </div>}

      {activeTab === 'materialise' && <div className="form-section">
        <h3>Materialise child</h3>
        <ChannelOpenForm
          mode="materialise"
          state={state}
          runAction={runAction}
          busy={busy}
          actionLabel="Materialise factory child"
          submitLabel="Materialise child"
          submitTestId="factory-materialise-child"
          testPrefix="factory-child"
          submitIcon={<Network size={15} />}
          prefill={materialisePrefill}
          disabled={!selectedFactoryId || orderedFactories.length === 0}
          peers={state.peers}
          beforeFields={(
            <FactorySelect testId="factory-materialise-select" factories={orderedFactories} value={selectedFactoryId} onChange={setSelectedFactoryId} />
          )}
          onSubmit={body => {
            const id = assertHex32(selectedFactoryId, 'Factory id');
            return postAction(`/api/factories/${id}/materialise-child`, body);
          }}
        />
      </div>}
    </div>
  );
}

function ChannelOpenForm({
  mode,
  state,
  runAction,
  busy,
  actionLabel,
  submitLabel,
  submitTestId,
  testPrefix,
  submitIcon,
  onSubmit,
  beforeFields,
  disabled = false,
  prefill,
  peers = [],
}: {
  mode: ChannelFormMode;
  state: NodeState;
  runAction: RunAction;
  busy: boolean;
  actionLabel: string;
  submitLabel: string;
  submitTestId: string;
  testPrefix: string;
  submitIcon: React.ReactNode;
  onSubmit: (body: ReturnType<typeof channelBody>) => Promise<NodeState>;
  beforeFields?: React.ReactNode;
  disabled?: boolean;
  prefill?: ChannelFormPrefill | null;
  peers?: PeerRecord[];
}) {
  const [draft, setDraft] = useState<ChannelFormDraft>(() => createChannelDraft());
  const child = mode === 'materialise';
  const usePeerSelect = child && peers.length > 0;
  const idLabel = child ? 'Child channel id' : 'Channel id';
  const idTestId = child ? `${testPrefix}-channel-id` : 'channel-id';

  useEffect(() => {
    if (!prefill) return;
    setDraft(current => ({ ...current, ...prefill.draft }));
  }, [prefill?.nonce]);

  useEffect(() => {
    if (!usePeerSelect) return;
    setDraft(current => (
      current.counterpartyPubkey
        ? current
        : { ...current, counterpartyPubkey: peers[0].pubkey, counterpartyAlias: '' }
    ));
  }, [usePeerSelect, peers]);

  const updateDraft = <Key extends keyof ChannelFormDraft>(key: Key, value: ChannelFormDraft[Key]) => {
    setDraft(current => ({ ...current, [key]: value }));
  };

  const generateIds = () => {
    setDraft(current => ({
      ...current,
      channelId: randomHex32(),
      fundingContextId: randomHex32(),
    }));
  };

  const submit = (event: FormEvent) => {
    event.preventDefault();
    void runAction(actionLabel, () => onSubmit(channelBody({
      channelId: draft.channelId,
      counterpartyPubkey: draft.counterpartyPubkey,
      counterpartyAlias: draft.counterpartyAlias,
      fundingContextId: draft.fundingContextId,
      local: draft.local,
      remote: draft.remote,
      pending: draft.pending,
      sponsorBudget: draft.sponsorBudget,
      asset: draft.asset,
      localPubkey: state.pubkey,
      child,
    })));
  };

  return (
    <form onSubmit={submit} className="form-grid">
      {beforeFields}
      <div className="field-action-row">
        <button type="button" className="field-action" data-testid={child ? 'factory-child-generate-ids' : 'channel-generate-ids'} onClick={generateIds}>
          <RefreshCw size={12} /> Generate ids
        </button>
      </div>
      <ValidatedInput label={idLabel} className="mono" testId={idTestId} value={draft.channelId} onChange={value => updateDraft('channelId', value)} validate={value => { assertHex32(value, idLabel); }} />
      {usePeerSelect ? (
        <label>Counterparty
          <select data-testid={`${testPrefix}-counterparty-pubkey`} value={draft.counterpartyPubkey} onChange={event => updateDraft('counterpartyPubkey', event.target.value)}>
            {peers.map(peer => (
              <option key={peer.pubkey} value={peer.pubkey}>{peer.alias || shortHex(peer.pubkey)} · {shortHex(peer.pubkey)}</option>
            ))}
          </select>
        </label>
      ) : (
        <>
          <ValidatedInput label="Counterparty pubkey" className="mono" testId={`${testPrefix}-counterparty-pubkey`} value={draft.counterpartyPubkey} onChange={value => updateDraft('counterpartyPubkey', value)} validate={value => { assertRemotePubkey(value, state.pubkey, 'Counterparty pubkey'); }} />
          <ValidatedInput label="Counterparty alias" testId={`${testPrefix}-counterparty-alias`} value={draft.counterpartyAlias} maxLength={MAX_PEER_ALIAS_LEN} onChange={value => updateDraft('counterpartyAlias', value)} validate={() => {}} />
        </>
      )}
      <ValidatedInput label="Funding context id" className="mono" testId={`${testPrefix}-funding-context-id`} value={draft.fundingContextId} onChange={value => updateDraft('fundingContextId', value)} validate={value => { assertHex32(value, 'Funding context id'); }} />
      <ValidatedInput label="Local capacity" className="mono" testId={`${testPrefix}-local`} value={draft.local} onChange={value => updateDraft('local', value)} validate={value => { assertPositiveInteger(value, 'Local capacity'); }} />
      <ValidatedInput label="Remote capacity" className="mono" testId={`${testPrefix}-remote`} value={draft.remote} onChange={value => updateDraft('remote', value)} validate={value => { assertPositiveInteger(value, 'Remote capacity'); }} />
      <ValidatedInput label="Pending capacity" className="mono" testId={`${testPrefix}-pending`} value={draft.pending} onChange={value => updateDraft('pending', value)} validate={value => { assertNonNegativeInteger(value, 'Pending capacity'); }} />
      <ValidatedInput label="Sponsor budget" className="mono" testId={`${testPrefix}-sponsor-budget`} value={draft.sponsorBudget} onChange={value => updateDraft('sponsorBudget', value)} validate={value => { assertPositiveInteger(value, 'Sponsor budget'); }} />
      <AssetSelect value={draft.asset} onChange={asset => updateDraft('asset', asset)} />
      <button data-testid={submitTestId} disabled={busy || disabled}>{submitIcon}{submitLabel}</button>
    </form>
  );
}

export function StateActions({ state, runAction, busy }: { state: NodeState; runAction: RunAction; busy: boolean }) {
  const [raw, setRaw] = useState('');
  const [stateFileStatus, setStateFileStatus] = useState('');
  const [stateFileBusy, setStateFileBusy] = useState(false);
  const [restoreAcknowledged, setRestoreAcknowledged] = useState(false);
  const [restoreCandidate, setRestoreCandidate] = useState<{ payload: unknown } | null>(null);

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

  const requestRestore = () => {
    setStateFileStatus('');
    try {
      setRestoreCandidate({ payload: JSON.parse(requiredText(raw, 'State file JSON')) });
    } catch (err) {
      setStateFileStatus(String((err as Error).message));
    }
  };

  const restoreState = () => {
    const candidate = restoreCandidate;
    if (candidate == null) return;
    void runAction('Restore state file', () => replaceStateFile(candidate.payload)).then(() => {
      setRestoreCandidate(null);
      setRestoreAcknowledged(false);
    });
  };

  return (
    <div className="drawer-section">
      <h2>State File</h2>
      <div className="state-path">
        <strong>{state.state_path || 'not loaded'}</strong>
        <small>{state.security.state_restore_enabled ? 'Empty bootstrap restore is enabled for this API process' : 'Restore is disabled by default'}</small>
      </div>
      <button className="copy-button" data-testid="state-load-json" onClick={exportState} disabled={busy || stateFileBusy}><FileJson size={15} /> Load state JSON</button>
      {stateFileStatus && <small className={stateFileStatus === 'loaded' ? 'inline-ok' : 'inline-error'}>{stateFileStatus}</small>}
      <textarea className="mono" data-testid="state-json" value={raw} onChange={event => setRaw(event.target.value)} />
      <label className="check-row">
        <input
          type="checkbox"
          checked={restoreAcknowledged}
          onChange={event => setRestoreAcknowledged(event.target.checked)}
          disabled={!state.security.state_restore_enabled}
        />
        <span>I understand this only restores an empty bootstrap state. Operational records are rejected until chain-anchored restore is implemented.</span>
      </label>
      <button
        className="danger-button"
        data-testid="state-restore-json"
        onClick={requestRestore}
        disabled={busy || !raw.trim() || !state.security.state_restore_enabled || !restoreAcknowledged}
      >
        <Upload size={15} /> Restore state file
      </button>
      {!state.security.state_restore_enabled && (
        <small className="inline-error">Restart with --allow-state-restore to enable this write path.</small>
      )}
      {restoreCandidate != null && (
        <ConfirmActionDialog
          title="Restore local Hub state file?"
          detail={`This replaces ${state.state_path || 'the current Hub state file'} with the JSON in the editor. The API writes a private backup of the previous file before the replacement is committed.`}
          confirmLabel="Restore"
          confirmTestId="confirm-state-restore"
          busy={busy}
          onCancel={() => setRestoreCandidate(null)}
          onConfirm={restoreState}
        />
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

function validationError(value: string, validate: (value: string) => void): string {
  try {
    validate(value);
    return '';
  } catch (err) {
    return err instanceof Error ? err.message : String(err);
  }
}

function requiredText(value: string, label: string): string {
  const trimmed = value.trim();
  if (!trimmed) throw new Error(`${label} must not be empty.`);
  return trimmed;
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values.map(value => value.trim()).filter(Boolean))];
}

function createChannelDraft(overrides: Partial<ChannelFormDraft> = {}): ChannelFormDraft {
  return {
    channelId: createDraftHex32(),
    counterpartyPubkey: '',
    counterpartyAlias: '',
    fundingContextId: createDraftHex32(),
    local: '',
    remote: '',
    pending: DEFAULT_PENDING_CAPACITY,
    sponsorBudget: DEFAULT_SPONSOR_BUDGET,
    asset: { kind: 'ckb' },
    ...overrides,
  };
}

function createDraftHex32(): string {
  try {
    return randomHex32();
  } catch {
    return '';
  }
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
function sortInvoicesNewestFirst(invoices: InvoiceRecord[]): InvoiceRecord[] {
  return [...invoices].sort((left, right) => {
    const byCreatedAt = right.created_at_unix - left.created_at_unix;
    return byCreatedAt || right.invoice_id.localeCompare(left.invoice_id);
  });
}

function newestInvoice(invoices: InvoiceRecord[]): InvoiceRecord | undefined {
  return sortInvoicesNewestFirst(invoices)[0];
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
