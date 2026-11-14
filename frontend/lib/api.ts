/**
 * Typed client for the SentinelForge REST API.
 *
 * Requests go to `NEXT_PUBLIC_API_URL` when set (e.g. http://localhost:8000),
 * otherwise to the same origin, where `next.config.js` rewrites `/api/*` to the
 * backend. A JWT stored by the login page is attached as a Bearer token.
 */

export const API_BASE = process.env.NEXT_PUBLIC_API_URL || '';

const TOKEN_KEY = 'sf_token';

export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

export function getToken(): string | null {
  if (typeof window === 'undefined') return null;
  try {
    return window.localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setToken(token: string | null): void {
  if (typeof window === 'undefined') return;
  try {
    if (token) window.localStorage.setItem(TOKEN_KEY, token);
    else window.localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage unavailable (private mode) — the session simply isn't persisted */
  }
}

export interface Session {
  email: string;
  name: string;
  role: string;
  expiresAt: number | null;
}

/**
 * Read display details from the stored JWT. This is for the UI only (showing
 * who is signed in); the backend verifies the signature on every request.
 */
export function getSession(): Session | null {
  const token = getToken();
  if (!token) return null;
  try {
    const part = token.split('.')[1];
    const json = atob(part.replace(/-/g, '+').replace(/_/g, '/'));
    const claims = JSON.parse(json);
    const expiresAt = typeof claims.exp === 'number' ? claims.exp * 1000 : null;
    if (expiresAt && expiresAt < Date.now()) return null;
    return { email: claims.sub ?? '', name: claims.name ?? '', role: claims.role ?? '', expiresAt };
  } catch {
    return null;
  }
}

export function logout(): void {
  setToken(null);
}

export function apiUrl(path: string): string {
  return `${API_BASE}${path}`;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body !== undefined && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  const token = getToken();
  if (token) headers.set('Authorization', `Bearer ${token}`);

  let res: Response;
  try {
    res = await fetch(apiUrl(path), { ...init, headers });
  } catch {
    throw new ApiError(0, 'Cannot reach the SentinelForge API');
  }

  if (!res.ok) {
    let detail = res.statusText || `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (body && typeof body.detail === 'string') detail = body.detail;
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, detail);
  }
  return (await res.json()) as T;
}

const get = <T>(path: string) => request<T>(path);
const post = <T>(path: string, body?: unknown) =>
  request<T>(path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) });

/* ----------------------------------------------------------------- types */

/**
 * A loosely-typed JSON record. Several endpoints return JSONB documents
 * (triage results, STIX rules, steps) whose shape varies by incident; pages
 * read them defensively with optional chaining.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type ApiRecord = { [key: string]: any };

export interface IncidentSummary {
  id: string;
  severity: string;
  status: string;
  affected_service: string;
  alert_message: string;
  created_at: string;
  alert_count?: number;
}

export interface IngestResult {
  accepted: boolean;
  incident_id?: string;
  correlated_into?: string;
  alert_count?: number;
  reason?: string;
}

export interface LoginResult {
  token: string;
  role: string;
  name: string;
}

/* -------------------------------------------------------------- endpoints */

export async function login(email: string, password: string): Promise<LoginResult> {
  const data = await post<LoginResult>('/api/v1/auth/login', { email, password });
  setToken(data.token);
  return data;
}

export const fetchIncidents = (limit = 50) =>
  get<{ incidents: IncidentSummary[]; count: number }>(`/api/v1/incidents?limit=${limit}`);

export const fetchIncident = (id: string) =>
  get<ApiRecord>(`/api/v1/incidents/${encodeURIComponent(id)}`);

export const fetchIncidentSteps = (id: string) =>
  get<{ steps: ApiRecord[]; count: number }>(`/api/v1/incidents/${encodeURIComponent(id)}/steps`);

export const fetchIncidentEvents = (id: string, limit = 500) =>
  get<{ events: ApiRecord[]; count: number }>(
    `/api/v1/incidents/${encodeURIComponent(id)}/events?limit=${limit}`,
  );

export const fetchPendingApprovals = () =>
  get<{ pending: ApiRecord[]; count: number }>('/api/v1/approvals/pending');

export const approveStep = (stepId: string, rationale?: string) =>
  post<{ step_id: string; status: string }>(
    `/api/v1/approvals/${encodeURIComponent(stepId)}/approve`,
    { rationale: rationale || null },
  );

export const rejectStep = (stepId: string, rationale?: string) =>
  post<{ step_id: string; status: string }>(
    `/api/v1/approvals/${encodeURIComponent(stepId)}/reject`,
    { rationale: rationale || null },
  );

export const escalateStep = (stepId: string, rationale?: string) =>
  post<{ step_id: string; status: string }>(
    `/api/v1/approvals/${encodeURIComponent(stepId)}/escalate`,
    { rationale: rationale || null },
  );

export const generateIncidentHunt = (id: string) =>
  post<ApiRecord>(`/api/v1/incidents/${encodeURIComponent(id)}/hunt`);

export const generateDetectionRule = (id: string) =>
  post<{ rule: ApiRecord; yaml: string; path: string }>(
    `/api/v1/incidents/${encodeURIComponent(id)}/detection-rule`,
  );

export const submitFeedback = (id: string, humanVerdict: string, note?: string) =>
  post<{ ok: boolean }>(`/api/v1/incidents/${encodeURIComponent(id)}/feedback`, {
    human_verdict: humanVerdict,
    note: note ?? null,
  });

export const ingestText = (text: string) => post<IngestResult>('/api/v1/ingest/text', { text });

export const fetchMTTR = () =>
  get<{ avg_mttr_seconds: number; resolved_count: number }>('/api/v1/analytics/mttr');

export const fetchByService = () =>
  get<{ services: { affected_service: string; count: number }[] }>('/api/v1/analytics/by-service');

export const fetchByVerdict = () =>
  get<{ verdicts: { verdict: string; count: number }[] }>('/api/v1/analytics/by-verdict');

export const fetchTopTechniques = () =>
  get<{ techniques: ApiRecord[] }>('/api/v1/analytics/top-techniques');

export const fetchSummary = () => get<ApiRecord>('/api/v1/analytics/summary');

/** Token usage per model (the analytics page's "usage" panel). */
export const fetchAnalytics = () =>
  get<{
    usage: {
      qwen_model: string;
      input_tokens: number;
      output_tokens: number;
      thinking_tokens: number;
      calls: number;
    }[];
  }>('/api/v1/analytics/token-usage');

export const fetchSecurityEvents = (limit = 50) =>
  get<{ events: ApiRecord[] }>(`/api/v1/security/events?limit=${limit}`);

export const fetchSecurityControls = () =>
  get<{ controls: ApiRecord[] }>('/api/v1/security/controls');
