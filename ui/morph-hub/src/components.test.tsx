import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ConfirmActionDialog, ValidatedInput } from './components';

afterEach(cleanup);

describe('ConfirmActionDialog', () => {
  function Harness() {
    const [open, setOpen] = useState(false);
    return (
      <>
        <button type="button" onClick={() => setOpen(true)}>Open confirmation</button>
        {open && (
          <ConfirmActionDialog
            title="Finalise channel?"
            detail="This cannot be undone."
            confirmLabel="Finalise"
            busy={false}
            onCancel={() => setOpen(false)}
            onConfirm={vi.fn()}
          />
        )}
      </>
    );
  }

  it('contains focus, closes on Escape, and restores the trigger focus', async () => {
    const user = userEvent.setup();
    render(<Harness />);
    const trigger = screen.getByRole('button', { name: 'Open confirmation' });

    await user.click(trigger);
    const cancel = screen.getByRole('button', { name: 'Cancel' });
    const confirm = screen.getByRole('button', { name: 'Finalise' });
    expect(document.activeElement).toBe(cancel);

    await user.tab();
    expect(document.activeElement).toBe(confirm);
    await user.tab();
    expect(document.activeElement).toBe(cancel);

    await user.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(document.activeElement).toBe(trigger);
  });

  it('allows the backdrop to cancel', async () => {
    const user = userEvent.setup();
    const { container } = render(<Harness />);
    await user.click(screen.getByRole('button', { name: 'Open confirmation' }));
    const backdrop = container.querySelector('.modal-backdrop');
    expect(backdrop).not.toBeNull();
    fireEvent.mouseDown(backdrop as Element);
    expect(screen.queryByRole('dialog')).toBeNull();
  });
});

describe('ValidatedInput', () => {
  it('connects a consistent inline error to the invalid input', async () => {
    const user = userEvent.setup();
    render(
      <ValidatedInput
        label="Alias"
        value=""
        onChange={vi.fn()}
        validate={() => { throw new Error('Alias is required.'); }}
      />
    );
    const input = screen.getByRole('textbox', { name: 'Alias' });
    await user.click(input);
    await user.tab();
    expect(input.getAttribute('aria-invalid')).toBe('true');
    const errorId = input.getAttribute('aria-describedby');
    expect(errorId).toBeTruthy();
    expect(document.getElementById(errorId ?? '')?.textContent).toBe('Alias is required.');
  });
});
