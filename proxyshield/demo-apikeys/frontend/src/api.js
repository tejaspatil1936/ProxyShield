export const API = import.meta.env.VITE_API_URL || '';

const TOKEN_KEY = 'kv_token';

export function getToken() {
  try { return localStorage.getItem(TOKEN_KEY) || ''; } catch { return ''; }
}

export function setToken(token) {
  try {
    if (token) localStorage.setItem(TOKEN_KEY, token);
    else localStorage.removeItem(TOKEN_KEY);
  } catch { /* ignore storage errors */ }
}

// authFetch prefixes the API base and attaches the stored Bearer token so the
// backend's requireAuth middleware accepts the request.
export function authFetch(path, opts = {}) {
  const token = getToken();
  const headers = { ...(opts.headers || {}) };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  return fetch(`${API}${path}`, { ...opts, headers });
}
