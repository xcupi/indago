// Minimal typed surface of the control API. The server's JSON is authoritative;
// these are the fields the UI reads, grouped by area.

export type ID = string;

export interface Project {
  id: ID;
  name: string;
  notes?: string;
  auth_state_path?: string;
  hunting_user_agent?: string;
  hunting_user_agent_replace?: boolean;
  created_at: string;
  updated_at?: string;
}

export interface AuthProfile {
  id: ID;
  project_id: ID;
  name: string;
  login_url?: string;
  success_url?: string;
  state_path?: string;
  created_at: string;
  updated_at?: string;
}

export interface Target {
  id: ID;
  project_id: ID;
  name: string;
  base_url: string;
  auth_profile_id?: ID;
  created_at: string;
}

export interface Scope {
  project_id: ID;
  include_hosts: string[];
  exclude_hosts: string[];
  include_path_prefixes: string[];
  exclude_path_prefixes: string[];
  allow_subdomains: boolean;
}

export interface ScanStats {
  endpoints_discovered: number;
  parameters_discovered: number;
  jobs_queued: number;
  jobs_completed: number;
  jobs_failed?: number;
  jobs_canceled?: number;
  jobs_total?: number;
  findings_confirmed: number;
  findings_rejected: number;
  findings_inconclusive: number;
}

export interface ScanConfig {
  discovery_concurrency?: number;
  http_concurrency?: number;
  browser_concurrency?: number;
  requests_per_second?: number;
  max_depth?: number;
  max_pages?: number;
  max_endpoints?: number;
}

export interface Scan {
  id: ID;
  project_id: ID;
  target_id: ID;
  name?: string;
  state: string;
  profile: string;
  config: ScanConfig;
  stop?: { mode?: string; confirmed_limit?: number };
  session_id?: string;
  seed_urls?: string[];
  discovery?: string;
  stats: ScanStats;
  error?: string;
  created_at: string;
  started_at?: string;
  updated_at: string;
  ended_at?: string;
}

export interface Finding {
  id: ID;
  scan_id: ID;
  project_id?: ID;
  vuln_class: string;
  verdict: string;
  severity: string;
  confidence: string;
  title: string;
  summary?: string;
  endpoint_id?: ID;
  location?: string;
  evidence_ids?: ID[];
  provenance?: { engine?: string; discovery_source?: string; detected_at?: string };
  detail?: string;
  created_at: string;
  updated_at?: string;
}

export interface Evidence {
  id: ID;
  scan_id: ID;
  finding_id?: ID;
  kind: string;
  media_type?: string;
  size: number;
  sha256?: string;
  note?: string;
  created_at: string;
}

/** Evidence metadata as returned by GET /api/scans/{id}/evidence. */
export interface EvidenceView {
  id: ID;
  kind: string;
  role: "baseline" | "candidate" | "browser" | string;
  media_type?: string;
  size: number;
  sha256?: string;
  created_at: string;
}

/** The scan evidence endpoint groups evidence under the finding it backs. */
export interface ScanEvidenceGroup {
  finding_id: ID;
  finding_title: string;
  verdict: string;
  section: string;
  verified_candidate?: string;
  evidence: EvidenceView[];
}

export interface Report {
  id: ID;
  scan_id: ID;
  project_id?: ID;
  format: string;
  template?: string;
  path?: string;
  summary?: Record<string, unknown>;
  created_at: string;
}

export interface EndpointRow {
  id: ID;
  scan_id?: ID;
  method: string;
  url: string;
  content_type?: string;
  status?: string;
  dom?: { sinks?: string[] } | string;
  parameters?: Array<{ name: string; location: string; example?: string }>;
  [key: string]: unknown;
}

export interface TestRow {
  id: ID;
  scan_id?: ID;
  job_id?: string;
  vuln_class: string;
  status: string;
  outcome?: string;
  method?: string;
  url?: string;
  note?: string;
  error?: string;
  started_at?: string;
  finished_at?: string;
}

export interface Coverage {
  scan_id?: ID;
  [key: string]: unknown;
}

export interface Capabilities {
  version?: string;
  [key: string]: unknown;
}

export interface LLMConfigView {
  provider?: string;
  model?: string;
  base_url?: string;
  has_key?: boolean;
  api_key_env?: string;
  enabled?: boolean;
  [key: string]: unknown;
}
