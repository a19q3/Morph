import { BadgeCheck } from 'lucide-react';
import type React from 'react';
import { useEffect, useId, useRef, useState } from 'react';

const FOCUSABLE_SELECTOR = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(',');

export function useModalFocus(onClose: () => void, closeDisabled = false) {
  const dialogRef = useRef<HTMLDivElement | null>(null);
  const onCloseRef = useRef(onClose);
  const closeDisabledRef = useRef(closeDisabled);
  onCloseRef.current = onClose;
  closeDisabledRef.current = closeDisabled;

  useEffect(() => {
    const previouslyFocused = document.activeElement instanceof HTMLElement
      ? document.activeElement
      : null;
    const dialog = dialogRef.current;
    const initialFocus = dialog?.querySelector<HTMLElement>('[data-autofocus]')
      ?? dialog?.querySelector<HTMLElement>(FOCUSABLE_SELECTOR);
    initialFocus?.focus();

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !closeDisabledRef.current) {
        event.preventDefault();
        onCloseRef.current();
        return;
      }
      if (event.key !== 'Tab' || !dialogRef.current) return;

      const focusable = [...dialogRef.current.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)]
        .filter(element => !element.hasAttribute('disabled') && element.getAttribute('aria-hidden') !== 'true');
      if (focusable.length === 0) {
        event.preventDefault();
        dialogRef.current.focus();
        return;
      }

      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener('keydown', onKeyDown, true);
    return () => {
      document.removeEventListener('keydown', onKeyDown, true);
      previouslyFocused?.focus();
    };
  }, []);

  return dialogRef;
}

export function ConfirmActionDialog({
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
  const titleId = useId();
  const detailId = useId();
  const dialogRef = useModalFocus(onCancel, busy);
  const cancelFromBackdrop = (event: React.MouseEvent<HTMLDivElement>) => {
    if (event.target === event.currentTarget && !busy) onCancel();
  };

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={cancelFromBackdrop}>
      <div
        ref={dialogRef}
        className="confirm-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={detailId}
        tabIndex={-1}
        onMouseDown={event => event.stopPropagation()}
      >
        <div>
          <h3 id={titleId}>{title}</h3>
          <p id={detailId}>{detail}</p>
        </div>
        <div className="confirm-dialog-actions">
          <button type="button" className="copy-button" data-autofocus onClick={onCancel} disabled={busy}>Cancel</button>
          <button type="button" className="danger-button" data-testid={confirmTestId} onClick={onConfirm} disabled={busy}>
            <BadgeCheck size={15} /> {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

export function ValidatedInput({
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
  const errorId = useId();
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
        aria-invalid={Boolean(error)}
        aria-describedby={error ? errorId : undefined}
        onBlur={() => setTouched(true)}
        onChange={event => onChange(event.target.value)}
      />
      {error && <small className="field-error" id={errorId}>{error}</small>}
    </label>
  );
}

export function ValidatedTextarea({
  label,
  value,
  onChange,
  validate,
  testId,
  className,
  disabled,
}: {
  label: React.ReactNode;
  value: string;
  onChange: (value: string) => void;
  validate: (value: string) => void;
  testId?: string;
  className?: string;
  disabled?: boolean;
}) {
  const [touched, setTouched] = useState(false);
  const errorId = useId();
  const error = touched ? validationError(value, validate) : '';
  return (
    <label>
      {label}
      <textarea
        className={`${className ?? ''} ${error ? 'invalid' : ''}`.trim()}
        data-testid={testId}
        value={value}
        disabled={disabled}
        aria-invalid={Boolean(error)}
        aria-describedby={error ? errorId : undefined}
        onBlur={() => setTouched(true)}
        onChange={event => onChange(event.target.value)}
      />
      {error && <small className="field-error" id={errorId}>{error}</small>}
    </label>
  );
}

function validationError(value: string, validate: (value: string) => void): string {
  try {
    validate(value);
    return '';
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
}
