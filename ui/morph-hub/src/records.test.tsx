import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ChannelRecord } from './domain';
import { ChannelTable } from './records';

afterEach(cleanup);

describe('ChannelTable', () => {
  it('renders every recorded asset and its capacity allocation', () => {
    const typeHash = `0x${'a'.repeat(64)}` as const;
    const channel: ChannelRecord = {
      channel_id: `0x${'1'.repeat(64)}`,
      counterparty_pubkey: `02${'2'.repeat(64)}`,
      counterparty_node_id: `0x${'3'.repeat(64)}`,
      funding_epoch: 1,
      funding_context_id: `0x${'4'.repeat(64)}`,
      state_number: 2,
      phase: 'active',
      balances: [
        { asset: { kind: 'ckb' }, local: '100000000', remote: '0', pending: '0' },
        { asset: { kind: 'xudt', type_hash: typeHash }, local: '20', remote: '20', pending: '2' },
      ],
      sponsor_budget: 1_000_000,
      provenance: {
        source: 'hub_state_file',
        chain_status: 'not_chain_verified',
        label: 'Local only',
        message: 'Local record',
      },
    };

    render(
      <ChannelTable
        channels={[channel]}
        totalCount={1}
        searchActive={false}
        runAction={vi.fn()}
        busy={false}
        canWrite={false}
        onOpenAction={vi.fn()}
      />
    );

    expect(screen.getByText('1 CKB')).toBeTruthy();
    expect(screen.getByText('42 xUDT')).toBeTruthy();
    expect(screen.getByText(`xUDT ${typeHash.slice(0, 10)}...${typeHash.slice(-6)}`)).toBeTruthy();
    expect(screen.getAllByRole('img', { name: /allocation:/ })).toHaveLength(2);
  });
});
