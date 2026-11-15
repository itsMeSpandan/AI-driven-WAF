/**
 * Dashboard API client functions.
 * Connects to NEXT_PUBLIC_API_BASE (defaults to http://localhost:8000).
 */

export const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8000";

export function getAuthHeaders(): Record<string, string> {
  if (typeof window !== "undefined") {
    const token = localStorage.getItem("waf_admin_token");
    if (token) {
      return { Authorization: `Bearer ${token}` };
    }
  }
  return {};
}

export function setAuthToken(token: string | null) {
  if (typeof window !== "undefined") {
    if (token) {
      localStorage.setItem("waf_admin_token", token);
    } else {
      localStorage.removeItem("waf_admin_token");
    }
  }
}

export interface SummaryStats {
  total_requests: number;
  total_blocked: number;
  total_flagged: number;
  total_allowed: number;
  block_rate: number;
  flag_rate: number;
  avg_latency_ms: number;
}

export interface TimeSeriesPoint {
  timestamp: string;
  total: number;
  threats: number;
  blocked: number;
  flagged: number;
}

export interface AttackTypeItem {
  attack_type: string;
  count: number;
  percentage: number;
}

export interface TopEndpointItem {
  path: string;
  attack_count: number;
  total_count: number;
}

export interface TopIPItem {
  ip: string;
  total_requests: number;
  blocked_requests: number;
}

export interface ExplanationToken {
  token: string;
  text?: string;
  start?: number;
  end?: number;
  weight: number;
}

export interface LexicalFeatureNote {
  name: string;
  value: number;
  note: string;
}

export interface MatchedRuleDetail {
  id: string;
  category?: string;
  pattern?: string;
  description?: string;
}

export interface EventExplanation {
  matched_rule?: string | null;
  matched_rule_detail?: MatchedRuleDetail | null;
  top_tokens?: ExplanationToken[];
  features?: LexicalFeatureNote[];
  summary?: string;
  attack_type?: string;
  canonical_text?: string;
}

export interface EventItem {
  id: string;
  ts: string;
  client_ip: string;
  method: string;
  path: string;
  query_summary?: string;
  body_summary?: string;
  user_agent?: string;
  verdict: "allow" | "flag" | "block";
  attack_type: string;
  ml_score: number;
  rule_hit?: string | null;
  latency_ms: number;
  explanation?: EventExplanation;
  feedback?: "fp" | "tp" | null;
  model_version?: string;
  anomaly_flag?: string | null;
}

export interface WAFConfig {
  waf_mode: "monitor" | "block";
  ml_threshold: number;
  max_body_inspect_bytes: number;
  fail_mode: "open" | "closed";
  rate_limit_enabled?: boolean;
  rate_limit_window_sec?: number;
  rate_limit_burst?: number;
  rate_enforce?: boolean;
}

export interface ConfigAuditItem {
  id: number;
  ts: string;
  actor: string;
  key: string;
  old_value: string | null;
  new_value: string | null;
}

export interface ThresholdSweepPoint {
  threshold: number;
  fpr: number;
  recall: number;
  f1: number;
}

export async function fetchSummary(range = "24h"): Promise<SummaryStats> {
  const res = await fetch(`${API_BASE}/api/stats/summary?range=${range}`, {
    cache: "no-store",
  });
  if (!res.ok) throw new Error("Failed to fetch summary");
  return res.json();
}

export async function fetchTimeSeries(
  range = "24h",
  bucket = "1h"
): Promise<{ points: TimeSeriesPoint[] }> {
  const res = await fetch(
    `${API_BASE}/api/stats/timeseries?range=${range}&bucket=${bucket}`,
    { cache: "no-store" }
  );
  if (!res.ok) throw new Error("Failed to fetch time series");
  return res.json();
}

export async function fetchAttackTypes(
  range = "24h"
): Promise<{ items: AttackTypeItem[] }> {
  const res = await fetch(`${API_BASE}/api/stats/attack-types?range=${range}`, {
    cache: "no-store",
  });
  if (!res.ok) throw new Error("Failed to fetch attack types");
  return res.json();
}

export async function fetchTopEndpoints(
  limit = 5,
  range = "24h"
): Promise<{ items: TopEndpointItem[] }> {
  const res = await fetch(
    `${API_BASE}/api/stats/top-endpoints?limit=${limit}&range=${range}`,
    { cache: "no-store" }
  );
  if (!res.ok) throw new Error("Failed to fetch top endpoints");
  return res.json();
}

export async function fetchTopIPs(
  limit = 5,
  range = "24h"
): Promise<{ items: TopIPItem[] }> {
  const res = await fetch(
    `${API_BASE}/api/stats/top-ips?limit=${limit}&range=${range}`,
    { cache: "no-store" }
  );
  if (!res.ok) throw new Error("Failed to fetch top ips");
  return res.json();
}

export interface EventsFilterParams {
  limit?: number;
  offset?: number;
  verdict?: string;
  attack_type?: string;
  anomaly_flag?: string;
  feedback?: string;
  search?: string;
}

export async function fetchEvents(
  params: number | EventsFilterParams = 25,
  verdict?: string
): Promise<{ items: EventItem[]; total: number }> {
  const url = new URL(`${API_BASE}/api/events`);
  if (typeof params === "number") {
    url.searchParams.set("limit", String(params));
    if (verdict) url.searchParams.set("verdict", verdict);
  } else {
    if (params.limit !== undefined) url.searchParams.set("limit", String(params.limit));
    if (params.offset !== undefined) url.searchParams.set("offset", String(params.offset));
    if (params.verdict && params.verdict !== "all") url.searchParams.set("verdict", params.verdict);
    if (params.attack_type && params.attack_type !== "all") url.searchParams.set("attack_type", params.attack_type);
    if (params.anomaly_flag && params.anomaly_flag !== "all") url.searchParams.set("anomaly_flag", params.anomaly_flag);
    if (params.feedback && params.feedback !== "all") url.searchParams.set("feedback", params.feedback);
    if (params.search) url.searchParams.set("search", params.search);
  }

  const res = await fetch(url.toString(), {
    headers: { ...getAuthHeaders() },
    cache: "no-store",
  });
  if (!res.ok) throw new Error("Failed to fetch events");
  return res.json();
}

export async function fetchEventDetail(id: string): Promise<EventItem> {
  const res = await fetch(`${API_BASE}/api/events/${id}`, {
    headers: { ...getAuthHeaders() },
    cache: "no-store",
  });
  if (!res.ok) throw new Error("Failed to fetch event detail");
  return res.json();
}

export async function submitFeedback(
  id: string,
  feedback: "fp" | "tp" | "clear",
  notes?: string
): Promise<void> {
  const res = await fetch(`${API_BASE}/api/events/${id}/feedback`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...getAuthHeaders(),
    },
    body: JSON.stringify({ feedback, notes }),
  });
  if (!res.ok) throw new Error("Failed to submit feedback");
}

export async function fetchConfig(): Promise<WAFConfig> {
  const res = await fetch(`${API_BASE}/api/config`, {
    headers: { ...getAuthHeaders() },
    cache: "no-store",
  });
  if (!res.ok) throw new Error("Failed to fetch configuration");
  return res.json();
}

export async function updateConfig(config: WAFConfig): Promise<WAFConfig> {
  const res = await fetch(`${API_BASE}/api/config`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      ...getAuthHeaders(),
    },
    body: JSON.stringify(config),
  });
  if (!res.ok) throw new Error("Failed to update configuration");
  return res.json();
}

export async function fetchConfigAudit(limit = 20): Promise<{ items: ConfigAuditItem[]; total: number }> {
  const res = await fetch(`${API_BASE}/api/config/audit?limit=${limit}`, {
    headers: { ...getAuthHeaders() },
    cache: "no-store",
  });
  if (!res.ok) throw new Error("Failed to fetch configuration audit trail");
  return res.json();
}

export async function fetchThresholdSweep(): Promise<{
  active_threshold: number;
  suggested_threshold: number;
  points: ThresholdSweepPoint[];
}> {
  const res = await fetch(`${API_BASE}/api/config/threshold-sweep`, {
    headers: { ...getAuthHeaders() },
    cache: "no-store",
  });
  if (!res.ok) throw new Error("Failed to fetch threshold sweep");
  return res.json();
}

export interface AuthUser {
  username: string;
  authenticated: boolean;
  role: string;
}

export async function loginAdmin(username: string, password: string): Promise<string> {
  const res = await fetch(`${API_BASE}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || "Authentication failed");
  }
  const data = await res.json();
  setAuthToken(data.access_token);
  return data.access_token;
}

export async function fetchCurrentUser(): Promise<AuthUser | null> {
  try {
    const res = await fetch(`${API_BASE}/api/auth/me`, {
      headers: { ...getAuthHeaders() },
      cache: "no-store",
    });
    if (!res.ok) return null;
    return res.json();
  } catch {
    return null;
  }
}

export async function logoutAdmin(): Promise<void> {
  setAuthToken(null);
  await fetch(`${API_BASE}/api/auth/logout`, { method: "POST" }).catch(() => {});
}
