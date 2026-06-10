import { config as zodConfig } from 'zod';
import {
  ToolError,
  buildQueryString,
  clearAuthCache,
  findLocalStorageEntry,
  getAuthCache,
  getLocalStorage,
  parseRetryAfterMs,
  setAuthCache,
  waitUntil,
} from '@opentabs-dev/plugin-sdk';

// OneNote on cloud.microsoft enforces Trusted Types, which blocks zod's JIT
// eval probe (`new Function("")`). Disabling JIT here — before any z.object()
// schema is instantiated — prevents the CSP violation entirely.
if (typeof window !== 'undefined' && 'trustedTypes' in window) {
  zodConfig({ jitless: true });
}

const GRAPH_BASE = 'https://graph.microsoft.com/v1.0';

// MSAL client ID used by the OneNote consumer web app. Enterprise tenants on
// cloud.microsoft use their own client IDs and encrypt their MSAL cache at rest,
// so we rely primarily on the in-page interceptor / silent acquisition below
// rather than on reading a token for this fixed client ID.
const MSAL_CLIENT_ID = '2821b473-fe24-4c86-ba16-62834d6e80c3';

interface OneNoteAuth {
  token: string;
  expiresOn: number; // epoch seconds
}

const TOKEN_TTL_SECONDS = 3600;
const nowSeconds = (): number => Math.floor(Date.now() / 1000);

/**
 * Scopes that grant access to the OneNote Graph endpoints. A token must include
 * at least one of these to be usable — a bare User.Read token 403s on /me/onenote.
 */
const NOTES_SCOPES = ['notes.read', 'notes.readwrite', 'notes.create', 'notes.read.all', 'notes.readwrite.all'];

const hasNotesScope = (target: string): boolean => {
  const lower = target.toLowerCase();
  return NOTES_SCOPES.some(scope => lower.includes(scope));
};

// Token captured by intercepting OneNote's own fetch/XHR calls — used when MSAL
// tokens are encrypted at rest by the Protected Token Cache on cloud.microsoft.
let interceptedToken: OneNoteAuth | null = null;

const decodeJwt = (token: string): Record<string, unknown> => {
  try {
    const part = token.split('.')[1] ?? '';
    return JSON.parse(atob(part.replace(/-/g, '+').replace(/_/g, '/'))) as Record<string, unknown>;
  } catch {
    return {};
  }
};

const jwtScopes = (token: string): string => {
  const p = decodeJwt(token);
  return (p['scp'] ?? p['scope'] ?? '') as string;
};

/**
 * Search window globals for an MSAL PublicClientApplication instance and acquire
 * a Graph token silently. MSAL keeps decrypted tokens in memory even when the
 * localStorage entries are encrypted (ProtectedTokenCache). This works regardless
 * of injection timing.
 */
const tryAcquireMsalToken = async (): Promise<OneNoteAuth | null> => {
  try {
    const scopes = [
      ['https://graph.microsoft.com/Notes.ReadWrite'],
      ['https://graph.microsoft.com/Notes.Read'],
      ['https://graph.microsoft.com/Notes.ReadWrite.All'],
      ['https://graph.microsoft.com/Notes.Read.All'],
    ];

    // Search window for MSAL-like objects (PublicClientApplication has acquireTokenSilent + getAllAccounts)
    const candidates: unknown[] = [];
    for (const key of Object.keys(window)) {
      try {
        const val = (window as unknown as Record<string, unknown>)[key];
        if (
          val &&
          typeof val === 'object' &&
          typeof (val as Record<string, unknown>).acquireTokenSilent === 'function' &&
          typeof (val as Record<string, unknown>).getAllAccounts === 'function'
        ) {
          candidates.push(val);
        }
      } catch {
        /* skip non-enumerable */
      }
    }

    for (const msal of candidates) {
      const app = msal as {
        getAllAccounts: () => unknown[];
        acquireTokenSilent: (req: unknown) => Promise<{ accessToken: string } | undefined>;
      };
      const accounts = app.getAllAccounts();
      if (!accounts.length) continue;
      for (const scopeSet of scopes) {
        try {
          const result = await app.acquireTokenSilent({ scopes: scopeSet, account: accounts[0] });
          if (result?.accessToken) {
            console.warn('[opentabs-onenote] Acquired token via MSAL acquireTokenSilent');
            return { token: result.accessToken, expiresOn: nowSeconds() + TOKEN_TTL_SECONDS };
          }
        } catch {
          /* try next scope set */
        }
      }
    }
  } catch {
    /* ignore */
  }
  return null;
};

const captureToken = (url: string, authHeader: string): void => {
  if (interceptedToken) return;
  if (!authHeader.startsWith('Bearer ')) return;
  const isGraph = url.includes('graph.microsoft.com');
  const isOneNoteCloud = url.includes('onenote.cloud.microsoft');
  if (!isGraph && !isOneNoteCloud) return;
  const token = authHeader.slice(7);
  // Skip Graph tokens that lack Notes scopes — they 403 on /me/onenote endpoints.
  if (isGraph && !hasNotesScope(jwtScopes(token))) return;
  interceptedToken = { token, expiresOn: nowSeconds() + TOKEN_TTL_SECONDS };
  setAuthCache('onenote', interceptedToken);
  console.warn('[opentabs-onenote] Captured Bearer token via interceptor');
};

/**
 * Intercept both window.fetch and XMLHttpRequest to capture Bearer tokens from
 * OneNote's own API calls. The web app may capture window.fetch before our adapter
 * is injected, so XHR interception is the reliable fallback.
 */
const installFetchInterceptor = (): void => {
  // fetch interceptor — catches calls made after our injection
  try {
    const originalFetch = window.fetch.bind(window);
    window.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      try {
        const url = input instanceof Request ? input.url : String(input);
        const hdrs = init?.headers ?? (input instanceof Request ? input.headers : undefined);
        let authHeader: string | null = null;
        if (hdrs instanceof Headers) authHeader = hdrs.get('Authorization');
        else if (hdrs && typeof hdrs === 'object')
          authHeader = (hdrs as Record<string, string>)['Authorization'] ?? null;
        if (authHeader) captureToken(url, authHeader);
      } catch {
        /* never block real fetch */
      }
      return originalFetch(input, init);
    };
  } catch {
    /* ignore */
  }

  // XHR prototype patch — intercepts ALL XHR instances regardless of when the
  // constructor reference was captured, because all instances share the same prototype.
  try {
    const proto = XMLHttpRequest.prototype;
    const originalOpen = proto.open;
    const originalSetRequestHeader = proto.setRequestHeader;

    proto.open = function (
      this: XMLHttpRequest & { _otUrl?: string },
      method: string,
      url: string,
      ...rest: unknown[]
    ) {
      this._otUrl = url;
      return (originalOpen as Function).apply(this, [method, url, ...rest]);
    };

    proto.setRequestHeader = function (this: XMLHttpRequest & { _otUrl?: string }, name: string, value: string) {
      try {
        if (name.toLowerCase() === 'authorization' && this._otUrl) captureToken(this._otUrl, value);
      } catch {
        /* ignore */
      }
      return originalSetRequestHeader.call(this, name, value);
    };
  } catch {
    /* ignore */
  }
};

if (typeof window !== 'undefined') {
  installFetchInterceptor();
  // Proactively acquire token via MSAL in-memory cache so it's ready before the first tool call.
  tryAcquireMsalToken()
    .then(auth => {
      if (auth && !interceptedToken) {
        interceptedToken = auth;
        setAuthCache('onenote', auth);
      }
    })
    .catch(() => {
      /* ignore */
    });
}

/**
 * Search the MSAL v2 token cache for a valid Graph access token with Notes scopes.
 * Enterprise tenants store tokens here; entries without Notes scopes are skipped
 * so they don't cause 403s on the OneNote endpoints.
 */
const findMsalV2Token = (clientId: string): OneNoteAuth | null => {
  const tokenKeysRaw = getLocalStorage(`msal.2.token.keys.${clientId}`);
  if (!tokenKeysRaw) return null;

  let tokenKeys: { accessToken?: string[] };
  try {
    tokenKeys = JSON.parse(tokenKeysRaw);
  } catch {
    return null;
  }
  if (!tokenKeys.accessToken) return null;

  for (const key of tokenKeys.accessToken) {
    const raw = getLocalStorage(key);
    if (!raw) continue;
    try {
      const parsed = JSON.parse(raw);
      if (!parsed.secret) continue;

      const target: string = parsed.target ?? '';
      const matchesGraph =
        target.toLowerCase().includes('graph.microsoft.com') || key.toLowerCase().includes('graph.microsoft.com');
      if (!matchesGraph) continue;

      const expiresOn = Number.parseInt(parsed.expiresOn, 10);
      if (expiresOn && expiresOn * 1000 < Date.now()) continue;

      if (!hasNotesScope(target)) continue;

      return { token: parsed.secret, expiresOn: expiresOn || nowSeconds() + TOKEN_TTL_SECONDS };
    } catch {
      // skip invalid entries
    }
  }
  return null;
};

/**
 * Legacy MSAL v1 reader. The OneNote web app stores MSAL tokens in localStorage
 * with keys containing the target resource URL. Used as a final fallback when the
 * cache is not encrypted.
 */
const extractMsalToken = (): OneNoteAuth | null => {
  const tokenKeysEntry = findLocalStorageEntry(key => key === `msal.token.keys.${MSAL_CLIENT_ID}`);
  if (!tokenKeysEntry) return null;

  let tokenKeys: { accessToken?: string[] };
  try {
    tokenKeys = JSON.parse(tokenKeysEntry.value);
  } catch {
    return null;
  }

  const graphKey = tokenKeys.accessToken?.find(
    k => /(?:^|[\s/])graph\.microsoft\.com(?:[/\s]|$)/.test(k) || k.includes('notes.'),
  );
  if (!graphKey) return null;

  const entryStr = findLocalStorageEntry(key => key === graphKey);
  if (!entryStr) return null;

  let entry: { secret?: string; expiresOn?: string };
  try {
    entry = JSON.parse(entryStr.value);
  } catch {
    return null;
  }

  if (!entry.secret) return null;

  const expiresOn = Number(entry.expiresOn ?? 0);
  if (expiresOn > 0 && expiresOn < nowSeconds()) return null;

  return { token: entry.secret, expiresOn: expiresOn || nowSeconds() + TOKEN_TTL_SECONDS };
};

/**
 * Resolve a Graph access token for OneNote.
 * Priority: cache > document_start capture > in-page interceptor > MSAL v2 cache > legacy v1 cache.
 */
const getAuth = (): OneNoteAuth | null => {
  const cached = getAuthCache<OneNoteAuth>('onenote');
  if (cached && cached.expiresOn > nowSeconds()) return cached;

  // Token captured by the document_start content script interceptor — works even
  // when MSAL tokens are encrypted at rest (Protected Token Cache).
  const earlyCapture = (window as unknown as { __opentabs_auth?: { token: string } }).__opentabs_auth;
  if (earlyCapture?.token) {
    const auth: OneNoteAuth = { token: earlyCapture.token, expiresOn: nowSeconds() + TOKEN_TTL_SECONDS };
    setAuthCache('onenote', auth);
    return auth;
  }

  // Token captured from OneNote's own in-page API calls.
  if (interceptedToken && interceptedToken.expiresOn > nowSeconds()) return interceptedToken;

  console.warn('[opentabs-onenote] getAuth() searching localStorage, total keys:', localStorage.length);

  // Enterprise MSAL v2 cache, then legacy v1 cache.
  let auth = findMsalV2Token(MSAL_CLIENT_ID);
  if (!auth) auth = extractMsalToken();
  if (!auth) return null;

  setAuthCache('onenote', auth);
  return auth;
};

export const isAuthenticated = (): boolean => getAuth() !== null;

export const waitForAuth = (): Promise<boolean> =>
  waitUntil(() => isAuthenticated(), { interval: 500, timeout: 5000 }).then(
    () => true,
    () => false,
  );

/**
 * Calls the Microsoft Graph API for OneNote operations.
 * Auth is via MSAL bearer tokens extracted from localStorage.
 */
export const api = async <T>(
  endpoint: string,
  options: {
    method?: string;
    body?: Record<string, unknown> | string;
    query?: Record<string, string | number | boolean | undefined>;
    contentType?: string;
  } = {},
): Promise<T> => {
  const auth = getAuth();
  if (!auth) {
    clearAuthCache('onenote');
    throw ToolError.auth('Not authenticated — please log in to Microsoft OneNote.');
  }

  const qs = options.query ? buildQueryString(options.query) : '';
  const url = qs ? `${GRAPH_BASE}${endpoint}?${qs}` : `${GRAPH_BASE}${endpoint}`;

  const headers: Record<string, string> = {
    Authorization: `Bearer ${auth.token}`,
  };

  let fetchBody: string | undefined;
  if (options.body) {
    if (typeof options.body === 'string') {
      headers['Content-Type'] = options.contentType ?? 'text/html';
      fetchBody = options.body;
    } else {
      headers['Content-Type'] = 'application/json';
      fetchBody = JSON.stringify(options.body);
    }
  }

  let response: Response;
  try {
    response = await fetch(url, {
      method: options.method ?? 'GET',
      headers,
      body: fetchBody,
      signal: AbortSignal.timeout(30_000),
    });
  } catch (err: unknown) {
    if (err instanceof DOMException && err.name === 'TimeoutError')
      throw ToolError.timeout(`API request timed out: ${endpoint}`);
    if (err instanceof DOMException && err.name === 'AbortError') throw new ToolError('Request was aborted', 'aborted');
    throw new ToolError(`Network error: ${err instanceof Error ? err.message : String(err)}`, 'network_error', {
      category: 'internal',
      retryable: true,
    });
  }

  if (!response.ok) {
    const errorBody = (await response.text().catch(() => '')).substring(0, 512);

    if (response.status === 429) {
      const retryAfter = response.headers.get('Retry-After');
      const retryMs = retryAfter !== null ? parseRetryAfterMs(retryAfter) : undefined;
      throw ToolError.rateLimited(`Rate limited: ${endpoint} — ${errorBody}`, retryMs);
    }
    if (response.status === 401 || response.status === 403) {
      clearAuthCache('onenote');
      throw ToolError.auth(`Auth error (${response.status}): ${errorBody}`);
    }
    if (response.status === 404) throw ToolError.notFound(`Not found: ${endpoint} — ${errorBody}`);
    if (response.status === 400 || response.status === 422)
      throw ToolError.validation(`Validation error: ${endpoint} — ${errorBody}`);
    throw ToolError.internal(`API error (${response.status}): ${endpoint} — ${errorBody}`);
  }

  if (response.status === 204) return {} as T;
  return (await response.json()) as T;
};
