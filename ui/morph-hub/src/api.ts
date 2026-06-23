import type { NodeState } from './domain';

const apiBase = import.meta.env.VITE_MORPH_HUB_API_URL ?? '';
const bundledApiToken = import.meta.env.VITE_MORPH_HUB_AUTH_TOKEN ?? '';
const tokenStorageKey = 'morph-hub-api-token';

let sessionApiToken = readStoredToken();

export function hasApiToken(): boolean {
  return Boolean(currentApiToken());
}

export function setApiToken(token: string): void {
  sessionApiToken = token.trim();
  if (typeof window === 'undefined') return;
  if (sessionApiToken) {
    window.sessionStorage.setItem(tokenStorageKey, sessionApiToken);
  } else {
    window.sessionStorage.removeItem(tokenStorageKey);
  }
}

export async function getState(): Promise<NodeState> {
  return request<NodeState>('/api/state');
}

export async function getStateFile(): Promise<unknown> {
  return request<unknown>('/api/state-file');
}

export async function replaceStateFile(state: unknown): Promise<NodeState> {
  return request<NodeState>('/api/state-file', {
    method: 'PUT',
    body: JSON.stringify(state),
  });
}

export async function postAction(path: string, body?: unknown): Promise<NodeState> {
  return request<NodeState>(path, {
    method: 'POST',
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

export async function connectPeer(pubkey: string, alias: string): Promise<NodeState> {
  return postAction('/api/peers', { pubkey, alias });
}

export function openEventStream(): EventSource | null {
  if (currentApiToken() || typeof EventSource === 'undefined') return null;
  return new EventSource(`${apiBase}/api/events`);
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  const apiToken = currentApiToken();
  if (init.body !== undefined) headers.set('content-type', 'application/json');
  if (apiToken) headers.set('authorization', `Bearer ${apiToken}`);
  const response = await fetch(`${apiBase}${path}`, { ...init, headers });
  if (!response.ok) {
    const message = await readError(response);
    throw new Error(message);
  }
  return response.json() as Promise<T>;
}

async function readError(response: Response): Promise<string> {
  const text = await response.text();
  if (!text) return `${response.status} ${response.statusText}`;
  try {
    const parsed = JSON.parse(text) as { error?: string };
    return parsed.error ?? text;
  } catch {
    return text;
  }
}

function currentApiToken(): string {
  return sessionApiToken || bundledApiToken.trim();
}

function readStoredToken(): string {
  if (typeof window === 'undefined') return '';
  return window.sessionStorage.getItem(tokenStorageKey)?.trim() ?? '';
}
