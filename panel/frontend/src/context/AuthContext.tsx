import { createContext, useContext, useState, useEffect, ReactNode } from "react";
import { api, ApiError } from "../api";
import { logger } from "../utils/logger";

interface User {
  id: string;
  email: string;
  role: string;
  /// Set when an admin is logged in as this account (from `GET /auth/me`).
  impersonated_by?: { id: string; email: string } | null;
  /// Unix seconds at which the "log in as" session ends.
  impersonation_expires_at?: number | null;
}

interface TwoFaChallenge {
  temp_token: string;
}

interface AuthContextType {
  user: User | null;
  login: (email: string, password: string) => Promise<TwoFaChallenge | null>;
  verify2fa: (tempToken: string, code: string) => Promise<void>;
  logout: () => void;
  stopImpersonation: () => Promise<void>;
  loading: boolean;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("/api/auth/me", { credentials: "same-origin" })
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (data) setUser(data);
        // An account with no password and no authenticator re-authenticates by
        // signing in again with its identity provider. That callback redirects
        // to "/", so the way back to the page the user was actually on has to
        // be carried client-side.
        if (data && sessionStorage.getItem("dp:passkey-return")) {
          sessionStorage.removeItem("dp:passkey-return");
          window.location.replace("/account");
        }
      })
      .catch(() => { /* not logged in */ })
      .finally(() => setLoading(false));
  }, []);

  const login = async (email: string, password: string): Promise<TwoFaChallenge | null> => {
    const data = await api.post<{ user?: User; requires_2fa?: boolean; temp_token?: string }>("/auth/login", {
      email,
      password,
    });
    if (data.requires_2fa && data.temp_token) {
      return { temp_token: data.temp_token };
    }
    if (data.user) {
      setUser(data.user);
    }
    return null;
  };

  const verify2fa = async (tempToken: string, code: string) => {
    const data = await api.post<{ user: User }>("/auth/2fa/verify", {
      temp_token: tempToken,
      code,
    });
    setUser(data.user);
  };

  // Ends a "log in as" session. The backend blacklists the borrowed session and
  // restores the admin's own cookie when it is still valid (`restored`). Either
  // way the selected server is dropped and the page fully reloads, so every
  // context starts over as the right identity.
  const stopImpersonation = async () => {
    let restored = false;
    try {
      const data = await api.post<{ restored?: boolean }>("/auth/impersonate/stop");
      restored = data.restored === true;
    } catch (e) {
      logger.error("Stop impersonation error:", e);
    }
    localStorage.removeItem("dp-active-server");
    window.location.href = restored ? "/" : "/login";
  };

  const logout = () => {
    // Logging out while logged in as someone else returns to the admin account
    // (the backend treats both the same way); there is only one path for it.
    if (user?.impersonated_by) {
      void stopImpersonation();
      return;
    }
    api.post("/auth/logout").catch((e) => logger.error("Logout error:", e));
    // The selected server is per-BROWSER, not per-account, and the next account
    // to sign in here may not own it - a client owns no `servers` row at all, so
    // an inherited id makes `ServerScope` refuse every request with
    // "Server not found or access denied". Clearing it here stops the leak at
    // the source; `ServerContext` also self-heals a browser that is already dirty.
    localStorage.removeItem("dp-active-server");
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, login, verify2fa, logout, stopImpersonation, loading }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
