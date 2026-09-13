/**
 * Dedicated auth-token state for the Varden security administration UI.
 *
 * Control-plane API keys / bearer tokens must not share the durable
 * localStorage preference path used for filters. Default storage is
 * sessionStorage (survives reload within the tab session). An explicit
 * "remember" option opts into localStorage with clear security messaging.
 */

const TOKEN_SESSION_KEY = 'varden.token.session';
const TOKEN_LOCAL_KEY = 'varden.token';
const REMEMBER_KEY = 'varden.token.remember';

export type AuthTokenState = {
  token: string;
  remember: boolean;
};

function readRaw(storage: Storage, key: string): string {
  try {
    const raw = storage.getItem(key);
    if (!raw) return '';
    try {
      const parsed = JSON.parse(raw);
      return typeof parsed === 'string' ? parsed : String(parsed ?? '');
    } catch {
      return raw;
    }
  } catch {
    return '';
  }
}

function writeRaw(storage: Storage, key: string, value: string): void {
  try {
    if (!value) storage.removeItem(key);
    else storage.setItem(key, JSON.stringify(value));
  } catch {
    /* quota / private mode — ignore */
  }
}

/** Migrate legacy durable token into session storage once, then scrub localStorage. */
export function migrateLegacyTokenStorage(): void {
  if (typeof window === 'undefined') return;
  try {
    const legacy = readRaw(window.localStorage, TOKEN_LOCAL_KEY);
    const remember = window.localStorage.getItem(REMEMBER_KEY) === 'true';
    if (legacy && !remember) {
      if (!readRaw(window.sessionStorage, TOKEN_SESSION_KEY)) {
        writeRaw(window.sessionStorage, TOKEN_SESSION_KEY, legacy);
      }
      window.localStorage.removeItem(TOKEN_LOCAL_KEY);
    }
  } catch {
    /* ignore */
  }
}

export function loadAuthTokenState(): AuthTokenState {
  if (typeof window === 'undefined') return { token: '', remember: false };
  migrateLegacyTokenStorage();
  const remember = window.localStorage.getItem(REMEMBER_KEY) === 'true';
  if (remember) {
    return { token: readRaw(window.localStorage, TOKEN_LOCAL_KEY), remember: true };
  }
  return { token: readRaw(window.sessionStorage, TOKEN_SESSION_KEY), remember: false };
}

export function persistAuthTokenState(state: AuthTokenState): void {
  if (typeof window === 'undefined') return;
  const token = String(state.token || '');
  if (state.remember) {
    window.localStorage.setItem(REMEMBER_KEY, 'true');
    writeRaw(window.localStorage, TOKEN_LOCAL_KEY, token);
    window.sessionStorage.removeItem(TOKEN_SESSION_KEY);
  } else {
    window.localStorage.removeItem(REMEMBER_KEY);
    window.localStorage.removeItem(TOKEN_LOCAL_KEY);
    writeRaw(window.sessionStorage, TOKEN_SESSION_KEY, token);
  }
}

export function clearAuthToken(): void {
  if (typeof window === 'undefined') return;
  try {
    window.sessionStorage.removeItem(TOKEN_SESSION_KEY);
    window.localStorage.removeItem(TOKEN_LOCAL_KEY);
    window.localStorage.removeItem(REMEMBER_KEY);
  } catch {
    /* ignore */
  }
}

/** Redact secrets from accidental log / debug serialization. */
export function redactToken(token: string | null | undefined): string {
  const value = String(token || '');
  if (!value) return '';
  if (value.length <= 8) return '***';
  return `${value.slice(0, 4)}…${value.slice(-2)}`;
}
