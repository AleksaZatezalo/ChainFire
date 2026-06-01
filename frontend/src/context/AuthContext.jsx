import React, { createContext, useCallback, useContext, useEffect, useState } from "react";
import { authApi } from "../api/client.js";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser]       = useState(null);   // null = not loaded yet
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      // Ensure CSRF cookie is set first
      await authApi.csrf();
      const res = await authApi.me();
      if (res.data.authenticated) {
        setUser(res.data);
      } else {
        setUser(false);
      }
    } catch {
      setUser(false);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  const logout = useCallback(async () => {
    try { await authApi.logout(); } catch { /* ignore */ }
    setUser(false);
  }, []);

  return (
    <AuthContext.Provider value={{ user, loading, refresh, logout, setUser }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
