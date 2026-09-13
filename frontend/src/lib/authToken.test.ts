import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  clearAuthToken,
  loadAuthTokenState,
  migrateLegacyTokenStorage,
  persistAuthTokenState,
  redactToken,
} from './authToken';

function memoryStorage(): Storage {
  const map = new Map<string, string>();
  return {
    get length() {
      return map.size;
    },
    clear() {
      map.clear();
    },
    getItem(key: string) {
      return map.has(key) ? map.get(key)! : null;
    },
    key(index: number) {
      return Array.from(map.keys())[index] ?? null;
    },
    removeItem(key: string) {
      map.delete(key);
    },
    setItem(key: string, value: string) {
      map.set(key, String(value));
    },
  };
}

describe('authToken storage', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('defaults to sessionStorage and does not write localStorage', () => {
    const session = memoryStorage();
    const local = memoryStorage();
    vi.stubGlobal('window', { sessionStorage: session, localStorage: local });
    persistAuthTokenState({ token: 'admin-demo-key', remember: false });
    expect(session.getItem('varden.token.session')).toContain('admin-demo-key');
    expect(local.getItem('varden.token')).toBeNull();
    expect(local.getItem('varden.token.remember')).toBeNull();
    expect(loadAuthTokenState()).toEqual({ token: 'admin-demo-key', remember: false });
  });

  it('remember option uses localStorage explicitly', () => {
    const session = memoryStorage();
    const local = memoryStorage();
    vi.stubGlobal('window', { sessionStorage: session, localStorage: local });
    persistAuthTokenState({ token: 'secret-token', remember: true });
    expect(local.getItem('varden.token.remember')).toBe('true');
    expect(local.getItem('varden.token')).toContain('secret-token');
    expect(session.getItem('varden.token.session')).toBeNull();
    clearAuthToken();
    expect(local.getItem('varden.token')).toBeNull();
    expect(session.getItem('varden.token.session')).toBeNull();
  });

  it('migrates legacy localStorage token into sessionStorage', () => {
    const session = memoryStorage();
    const local = memoryStorage();
    local.setItem('varden.token', JSON.stringify('legacy-key'));
    vi.stubGlobal('window', { sessionStorage: session, localStorage: local });
    migrateLegacyTokenStorage();
    expect(session.getItem('varden.token.session')).toContain('legacy-key');
    expect(local.getItem('varden.token')).toBeNull();
  });

  it('redacts tokens for safe display', () => {
    expect(redactToken('abcdefghij')).toBe('abcd…ij');
    expect(redactToken('short')).toBe('***');
  });
});
