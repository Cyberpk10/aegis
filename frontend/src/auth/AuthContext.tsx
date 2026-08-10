import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { getMe, login as apiLogin, logout as apiLogout, signup as apiSignup, setOnAuthExpired } from "../api/authClient";
import { getAccessToken } from "./tokenStore";
import type { UserResponse } from "../types/auth";

type AuthStatus = "loading" | "authenticated" | "unauthenticated";

interface AuthContextValue {
  status: AuthStatus;
  user: UserResponse | null;
  login: (email: string, password: string) => Promise<void>;
  signup: (accountName: string, email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  /** Tokens are already stored (e.g. by authClient.acceptInvite) — this just brings React
   * state in sync so the app renders as authenticated without a page reload. */
  applySession: (user: UserResponse) => void;
  /** True for exactly one render cycle right after signup() resolves — lets App.tsx show
   * the forwarding-address screen once, before the dashboard, without any server-side
   * "has completed onboarding" flag. Never true after a login or a page reload. */
  justSignedUp: boolean;
  acknowledgeSignupWelcome: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<AuthStatus>("loading");
  const [user, setUser] = useState<UserResponse | null>(null);
  const [justSignedUp, setJustSignedUp] = useState(false);

  const dropSession = useCallback(() => {
    setUser(null);
    setStatus("unauthenticated");
  }, []);

  useEffect(() => {
    setOnAuthExpired(dropSession);
    return () => setOnAuthExpired(null);
  }, [dropSession]);

  useEffect(() => {
    if (!getAccessToken()) {
      setStatus("unauthenticated");
      return;
    }
    // apiFetch (used by getMe) transparently refreshes an expired access token using the
    // stored refresh token before giving up, so this also covers "access token expired
    // while the tab was closed" on reload.
    getMe()
      .then((fetchedUser) => {
        setUser(fetchedUser);
        setStatus("authenticated");
      })
      .catch(() => dropSession());
  }, [dropSession]);

  const login = useCallback(async (email: string, password: string) => {
    const response = await apiLogin(email, password);
    setUser(response.user);
    setStatus("authenticated");
  }, []);

  const signup = useCallback(async (accountName: string, email: string, password: string) => {
    const response = await apiSignup(accountName, email, password);
    setUser(response.user);
    setJustSignedUp(true);
    setStatus("authenticated");
  }, []);

  const logout = useCallback(async () => {
    await apiLogout();
    setJustSignedUp(false);
    dropSession();
  }, [dropSession]);

  const applySession = useCallback((sessionUser: UserResponse) => {
    setUser(sessionUser);
    setStatus("authenticated");
  }, []);

  const acknowledgeSignupWelcome = useCallback(() => setJustSignedUp(false), []);

  const value = useMemo<AuthContextValue>(
    () => ({
      status,
      user,
      login,
      signup,
      logout,
      applySession,
      justSignedUp,
      acknowledgeSignupWelcome,
    }),
    [status, user, login, signup, logout, applySession, justSignedUp, acknowledgeSignupWelcome]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
}
