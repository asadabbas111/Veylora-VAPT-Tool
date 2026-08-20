import axios, { AxiosError } from "axios";
import type { Tokens, User } from "./types";

const TOKEN_KEY = "apt_access";
const REFRESH_KEY = "apt_refresh";
const USER_KEY = "apt_user";

// Session-scoped storage on purpose: tokens never survive a new browser session,
// so opening the app always lands on the sign-in screen.
const store = window.sessionStorage;

export const api = axios.create({ baseURL: "/api", timeout: 120000 });

api.interceptors.request.use((cfg) => {
  const token = store.getItem(TOKEN_KEY);
  if (token) cfg.headers.Authorization = `Bearer ${token}`;
  return cfg;
});

api.interceptors.response.use(
  (res) => res,
  async (err: AxiosError) => {
    const original = err.config as any;
    if (
      err.response?.status === 401 &&
      !original?._retry &&
      store.getItem(REFRESH_KEY)
    ) {
      original._retry = true;
      try {
        const { data } = await axios.post<Tokens>("/api/auth/refresh", {
          refresh_token: store.getItem(REFRESH_KEY),
        });
        store.setItem(TOKEN_KEY, data.access_token);
        store.setItem(REFRESH_KEY, data.refresh_token);
        original.headers.Authorization = `Bearer ${data.access_token}`;
        return api(original);
      } catch {
        clearTokens();
        window.location.href = "/login";
        return Promise.reject(err);
      }
    }
    return Promise.reject(err);
  }
);

export const clearTokens = () => {
  store.removeItem(TOKEN_KEY);
  store.removeItem(REFRESH_KEY);
  store.removeItem(USER_KEY);
  // legacy keys written by an earlier build; harmless to remove
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(REFRESH_KEY);
  localStorage.removeItem(USER_KEY);
};

export const saveTokens = (t: Tokens, u: User) => {
  store.setItem(TOKEN_KEY, t.access_token);
  store.setItem(REFRESH_KEY, t.refresh_token);
  store.setItem(USER_KEY, JSON.stringify(u));
};

export const getStoredUser = (): User | null => {
  try {
    const raw = store.getItem(USER_KEY);
    return raw ? (JSON.parse(raw) as User) : null;
  } catch {
    return null;
  }
};

export const setStoredUser = (u: User) =>
  store.setItem(USER_KEY, JSON.stringify(u));

export function apiError(err: unknown): string {
  const e = err as AxiosError<{ detail?: unknown }>;
  const detail = e?.response?.data?.detail;
  if (typeof detail === "string" && detail) return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((d) => (typeof d === "object" && d !== null && "msg" in d ? String((d as { msg: string }).msg) : String(d)))
      .filter(Boolean)
      .join("; ");
  }
  if (e?.message) return e.message;
  return "Something went wrong.";
}