import { useEffect, useState } from "react";

// The control API refuses state-changing requests without this header
// (CSRF guard) and accepts an optional bearer token when the server was
// started behind INDAGO_API_TOKEN.
const CLIENT_HEADER = "X-Indago-Client";
const CLIENT_VALUE = "ui";
const TOKEN_KEY = "indago.token";

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

export function getToken(): string {
  return localStorage.getItem(TOKEN_KEY) ?? "";
}

export function setToken(token: string) {
  if (token) localStorage.setItem(TOKEN_KEY, token);
  else localStorage.removeItem(TOKEN_KEY);
}

export async function api<T>(
  path: string,
  init: { method?: string; body?: unknown } = {},
): Promise<T> {
  const headers: Record<string, string> = { [CLIENT_HEADER]: CLIENT_VALUE };
  if (init.body !== undefined) headers["Content-Type"] = "application/json";
  const token = getToken();
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const res = await fetch(path, {
    method: init.method ?? "GET",
    headers,
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
  });
  const text = await res.text();
  let data: unknown = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }
  if (!res.ok) {
    const message =
      data && typeof data === "object" && "error" in (data as Record<string, unknown>)
        ? String((data as Record<string, unknown>).error)
        : `HTTP ${res.status}`;
    throw new ApiError(message, res.status);
  }
  return data as T;
}

export function refreshAll() {
  window.dispatchEvent(new Event("indago:refresh"));
}

export interface AsyncState<T> {
  data?: T;
  error?: string;
  loading: boolean;
}

/** Read one API path, re-running on deps, on global refresh, and on an interval. */
export function useApi<T>(path: string | null, deps: unknown[] = [], pollMs = 0): AsyncState<T> {
  const [state, setState] = useState<AsyncState<T>>({ loading: Boolean(path) });
  const [tick, setTick] = useState(0);

  useEffect(() => {
    const onRefresh = () => setTick((t) => t + 1);
    window.addEventListener("indago:refresh", onRefresh);
    return () => window.removeEventListener("indago:refresh", onRefresh);
  }, []);

  useEffect(() => {
    if (!pollMs) return;
    const id = window.setInterval(() => setTick((t) => t + 1), pollMs);
    return () => window.clearInterval(id);
  }, [pollMs]);

  useEffect(() => {
    if (!path) {
      setState({ loading: false });
      return;
    }
    let alive = true;
    setState((prev) => ({ ...prev, loading: true, error: undefined }));
    api<T>(path)
      .then((data) => alive && setState({ data, loading: false }))
      .catch((err: Error) => alive && setState({ error: err.message, loading: false }));
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path, tick, ...deps]);

  return state;
}
