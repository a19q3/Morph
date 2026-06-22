import type { NodeState } from './domain';

const apiBase = import.meta.env.VITE_MORPH_HUB_API_URL ?? '';

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

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body !== undefined) headers.set('content-type', 'application/json');
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
