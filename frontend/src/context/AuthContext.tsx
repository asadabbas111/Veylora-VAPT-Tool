import React, { createContext, useContext, useEffect, useState } from "react";
import { api, getStoredUser, saveTokens, clearTokens, setStoredUser } from "../lib/api";
import type { Tokens, User } from "../lib/types";

interface AuthContextValue {
  user: User | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<User>;
  completeVerification: (tokens: Tokens, user: User) => void;
  logout: () => void;
  refreshMe: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue>(null!);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(() => getStoredUser());
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!user) return;
    api
      .get<{ user: User }>("/auth/me")
      .then((res) => {
        setUser(res.data.user);
        setStoredUser(res.data.user);
      })
      .catch(() => {});
  }, []);

  const login = async (email: string, password: string) => {
    const { data } = await api.post<Tokens>("/auth/login", { email, password });
    saveTokens(data, getStoredUser() ?? ({} as User));
    const me = await api.get<{ user: User }>("/auth/me");
    setStoredUser(me.data.user);
    setUser(me.data.user);
    return me.data.user;
  };

  const completeVerification = (tokens: Tokens, u: User) => {
    saveTokens(tokens, u);
    setUser(u);
  };

  const logout = () => {
    clearTokens();
    setUser(null);
  };

  const refreshMe = async () => {
    const { data } = await api.get<{ user: User }>("/auth/me");
    setUser(data.user);
    setStoredUser(data.user);
  };

  return (
    <AuthContext.Provider
      value={{ user, loading, login, completeVerification, logout, refreshMe }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);