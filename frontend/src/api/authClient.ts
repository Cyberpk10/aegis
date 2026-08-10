import type {
  InviteResponse,
  PasswordResetRequestResponse,
  TokenResponse,
  UserResponse,
  UserRole,
} from "../types/auth";
import { clearTokens, getAccessToken, getRefreshToken, setTokens } from "../auth/tokenStore";

// Empty by default (unset) so every relative /api/... URL below is unchanged in local dev —
// Vite's dev-server proxy (vite.config.ts) still handles it. In production, set
// VITE_API_BASE_URL to the deployed backend's origin. Mirrors api/client.ts exactly.
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "";

export class AuthError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

async function parseErrorOrThrow(response: Response): Promise<never> {
  const body = await response.json().catch(() => null);
  throw new AuthError(body?.detail ?? `Request failed with status ${response.status}`, response.status);
}

let onAuthExpired: (() => void) | null = null;

/** Registered once by AuthContext so apiFetch can flip global auth state to "unauthenticated"
 * when a refresh attempt fails, without api/client.ts needing to import React state directly. */
export function setOnAuthExpired(callback: (() => void) | null): void {
  onAuthExpired = callback;
}

async function refreshAccessToken(): Promise<boolean> {
  const refreshToken = getRefreshToken();
  if (!refreshToken) return false;

  const response = await fetch(`${API_BASE_URL}/api/auth/refresh`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: refreshToken }),
  });
  if (!response.ok) return false;

  const body: TokenResponse = await response.json();
  setTokens(body.access_token, body.refresh_token);
  return true;
}

/** The shared fetch wrapper every other module in src/api/ routes through. Attaches
 * `Authorization: Bearer <accessToken>`, and on a 401 transparently refreshes the access
 * token once and retries — the caller never has to think about token expiry. If the
 * refresh itself fails (expired/revoked refresh token), tokens are cleared and
 * `onAuthExpired` fires so the app can drop back to the login screen. */
export async function apiFetch(path: string, options: RequestInit = {}): Promise<Response> {
  const accessToken = getAccessToken();
  const headers = new Headers(options.headers);
  if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);

  let response = await fetch(`${API_BASE_URL}${path}`, { ...options, headers });

  if (response.status === 401 && getRefreshToken()) {
    const refreshed = await refreshAccessToken();
    if (refreshed) {
      const retryHeaders = new Headers(options.headers);
      retryHeaders.set("Authorization", `Bearer ${getAccessToken()}`);
      response = await fetch(`${API_BASE_URL}${path}`, { ...options, headers: retryHeaders });
    } else {
      clearTokens();
      onAuthExpired?.();
    }
  }

  return response;
}

export async function signup(
  accountName: string,
  email: string,
  password: string
): Promise<TokenResponse> {
  const response = await fetch(`${API_BASE_URL}/api/auth/signup`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ account_name: accountName, email, password }),
  });
  if (!response.ok) return parseErrorOrThrow(response);
  const body: TokenResponse = await response.json();
  setTokens(body.access_token, body.refresh_token);
  return body;
}

export async function login(email: string, password: string): Promise<TokenResponse> {
  const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  if (!response.ok) return parseErrorOrThrow(response);
  const body: TokenResponse = await response.json();
  setTokens(body.access_token, body.refresh_token);
  return body;
}

export async function logout(): Promise<void> {
  const refreshToken = getRefreshToken();
  clearTokens();
  if (!refreshToken) return;
  await fetch(`${API_BASE_URL}/api/auth/logout`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: refreshToken }),
  }).catch(() => undefined); // best-effort — tokens are already cleared client-side
}

export async function getMe(): Promise<UserResponse> {
  const response = await apiFetch("/api/auth/me");
  if (!response.ok) return parseErrorOrThrow(response);
  return response.json();
}

export async function requestPasswordReset(email: string): Promise<PasswordResetRequestResponse> {
  const response = await fetch(`${API_BASE_URL}/api/auth/password-reset/request`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });
  if (!response.ok) return parseErrorOrThrow(response);
  return response.json();
}

export async function confirmPasswordReset(token: string, newPassword: string): Promise<void> {
  const response = await fetch(`${API_BASE_URL}/api/auth/password-reset/confirm`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token, new_password: newPassword }),
  });
  if (!response.ok && response.status !== 204) return parseErrorOrThrow(response);
}

export async function acceptInvite(token: string, password: string): Promise<TokenResponse> {
  const response = await fetch(`${API_BASE_URL}/api/auth/invite/accept`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token, password }),
  });
  if (!response.ok) return parseErrorOrThrow(response);
  const body: TokenResponse = await response.json();
  setTokens(body.access_token, body.refresh_token);
  return body;
}

export async function sendInvite(email: string, role: UserRole): Promise<InviteResponse> {
  const response = await apiFetch("/api/auth/invite", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, role }),
  });
  if (!response.ok) return parseErrorOrThrow(response);
  return response.json();
}

export async function listUsers(): Promise<UserResponse[]> {
  const response = await apiFetch("/api/auth/users");
  if (!response.ok) return parseErrorOrThrow(response);
  const body: { items: UserResponse[] } = await response.json();
  return body.items;
}

export async function updateUserRole(userId: string, role: UserRole): Promise<UserResponse> {
  const response = await apiFetch(`/api/auth/users/${userId}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ role }),
  });
  if (!response.ok) return parseErrorOrThrow(response);
  return response.json();
}

export async function deleteUser(userId: string): Promise<void> {
  const response = await apiFetch(`/api/auth/users/${userId}`, { method: "DELETE" });
  if (!response.ok && response.status !== 204) return parseErrorOrThrow(response);
}
