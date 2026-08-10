// Both tokens live in localStorage, readable by an XSS bug — the standard tradeoff for a
// cross-*site* SPA+API split (frontend on vercel.app, backend on onrender.com), where a
// SameSite=None cookie would be genuinely fragile under browser third-party-cookie
// restrictions. Mitigated by a short access-token TTL (15 min) and rotating,
// server-revocable refresh tokens — see backend/app/auth/security.py.
const ACCESS_TOKEN_KEY = "aegis_access_token";
const REFRESH_TOKEN_KEY = "aegis_refresh_token";

export function getAccessToken(): string | null {
  return localStorage.getItem(ACCESS_TOKEN_KEY);
}

export function getRefreshToken(): string | null {
  return localStorage.getItem(REFRESH_TOKEN_KEY);
}

export function setTokens(accessToken: string, refreshToken: string): void {
  localStorage.setItem(ACCESS_TOKEN_KEY, accessToken);
  localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken);
}

export function clearTokens(): void {
  localStorage.removeItem(ACCESS_TOKEN_KEY);
  localStorage.removeItem(REFRESH_TOKEN_KEY);
}
