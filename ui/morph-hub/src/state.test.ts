import { describe, expect, it } from 'vitest';
import type { InvoiceRecord } from './domain';
import { invoiceExpiryLabel, requiredText, sortInvoicesNewestFirst } from './state';

function invoice(invoiceId: `0x${string}`, createdAt: number): InvoiceRecord {
  return {
    invoice_id: invoiceId,
    encoded_invoice: 'morph1example',
    status: 'open',
    network: 'devnet',
    payee_node_id: `0x${'1'.repeat(64)}`,
    asset: { kind: 'ckb' },
    amount: '1',
    created_at_unix: createdAt,
    expires_at_unix: createdAt + 3_600,
    payment_hash: `0x${'2'.repeat(64)}`,
    description: '',
    provenance: {
      source: 'hub_state_file',
      chain_status: 'not_chain_verified',
      label: 'Local only',
      message: 'Local record',
    },
  };
}

describe('shared state helpers', () => {
  it('uses one deterministic newest-invoice order including ties', () => {
    const older = invoice(`0x${'f'.repeat(64)}`, 10);
    const lowerTie = invoice(`0x${'1'.repeat(64)}`, 20);
    const higherTie = invoice(`0x${'e'.repeat(64)}`, 20);
    expect(sortInvoicesNewestFirst([older, lowerTie, higherTie]).map(item => item.invoice_id))
      .toEqual([higherTie.invoice_id, lowerTie.invoice_id, older.invoice_id]);
  });

  it('formats useful invoice countdown states', () => {
    const nowMs = 1_000_000;
    expect(invoiceExpiryLabel(1_030, nowMs)).toBe('expires in 30s');
    expect(invoiceExpiryLabel(1_000, nowMs)).toBe('expired');
    expect(invoiceExpiryLabel(1_000 + 3 * 3_600, nowMs)).toBe('expires in 3h');
  });

  it('normalises required text and uses one error message', () => {
    expect(requiredText('  morph  ', 'Name')).toBe('morph');
    expect(() => requiredText('  ', 'Name')).toThrow('Name is required.');
  });
});
