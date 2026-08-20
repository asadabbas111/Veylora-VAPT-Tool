export interface User {
  id: number;
  full_name: string;
  email: string;
  role: "admin" | "analyst" | "viewer";
  is_verified: boolean;
  is_active: boolean;
  last_login_at?: string | null;
  created_at: string;
}

export interface Tokens {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export interface Assessment {
  id: number;
  name: string;
  description?: string | null;
  client_name?: string | null;
  assessment_type: string;
  start_date: string;
  end_date?: string | null;
  rules_of_engagement?: string | null;
  validation_level: number;
  status: string;
  progress: number;
  stage: string;
  stage_log: Record<string, unknown>;
  owner_id: number;
  created_at: string;
  updated_at: string;
}

export interface Scope {
  id: number;
  assessment_id: number;
  target: string;
  target_type: string;
  description?: string | null;
  created_at: string;
}

export interface Target {
  id: number;
  assessment_id: number;
  target: string;
  target_type: string;
  in_scope: boolean;
  validation_note?: string | null;
  added_at: string;
}

export interface AssessmentDetail extends Assessment {
  scopes: Scope[];
  targets: Target[];
}

export interface Job {
  id: number;
  assessment_id?: number | null;
  task_type: string;
  status: string;
  progress: number;
  log: string;
  error?: string | null;
  created_at: string;
  started_at?: string | null;
  finished_at?: string | null;
}

export interface Service {
  id: number;
  asset_id: number;
  port: number;
  protocol: string;
  service_name: string;
  product?: string | null;
  version?: string | null;
  risk_score: number;
  metadata_json?: Record<string, unknown>;
}

export interface Asset {
  id: number;
  assessment_id: number;
  ip_address: string;
  hostname?: string | null;
  os_name?: string | null;
  os_version?: string | null;
  criticality: number;
  risk_score: number;
  first_seen: string;
  last_seen: string;
  metadata_json?: Record<string, unknown>;
  services?: Service[];
}

export interface Finding {
  id: number;
  assessment_id: number;
  asset_id: number;
  title: string;
  description?: string | null;
  cve?: string | null;
  cwe?: string | null;
  cvss_score?: number | null;
  cvss_vector?: string | null;
  severity: string;
  affected_service?: string | null;
  affected_port?: number | null;
  risk_score: number;
  risk_breakdown: Record<string, unknown>;
  status: string;
  confidence: number;
  detection_source?: string | null;
  remediation?: string | null;
  first_seen: string;
  last_seen: string;
}

export interface FindingDetail extends Finding {
  evidence: Evidence[];
  mitre_techniques: { technique_id: string; name: string; tactic: string }[];
  ai_priority?: string | null;
}

export interface Evidence {
  id: number;
  assessment_id: number;
  finding_id?: number | null;
  category: string;
  filename?: string | null;
  sha256: string;
  source?: string | null;
  captured_at: string;
  immutable: boolean;
  content?: string | null;
}

export interface AttackNode {
  node_id: string;
  id?: string;
  label?: string;
  node_type: string;
  ref_id?: number;
  order?: number;
  props?: Record<string, unknown>;
}

export interface AttackEdge {
  from?: string;
  to?: string;
  rel_type?: string;
}

export interface AttackPath {
  id: number;
  assessment_id: number;
  name: string;
  description?: string | null;
  start_node: string;
  end_node: string;
  end_node_type?: string | null;
  path_length: number;
  cumulative_risk: number;
  confidence: number;
  vulnerability_count: number;
  nodes_json?: AttackNode[];
  edges_json?: AttackEdge[] | string;
  is_current: boolean;
  created_at: string;
}

export interface GraphSummary {
  node_count: number;
  edge_count: number;
  path_count: number;
  max_risk: number;
  summary: string;
}

export interface AIAnalysis {
  id: number;
  finding_id: number;
  analysis_type: string;
  provider: string;
  model?: string | null;
  severity?: string | null;
  confidence: number;
  priority?: string | null;
  priority_deadline?: string | null;
  executive_summary?: string | null;
  technical_explanation?: string | null;
  risk_explanation?: string | null;
  attack_path_explanation?: string | null;
  false_positive_assessment?: string | null;
  false_positive_likelihood?: number | null;
  recommended_remediation?: string | null;
  basis?: unknown[];
  created_at: string;
}

export interface RemediationTask {
  id: number;
  finding_id: number;
  assessment_id: number;
  status: string;
  assignee_name?: string | null;
  deadline?: string | null;
  remediation_plan?: string | null;
  retest_before_score?: number | null;
  retest_after_score?: number | null;
  retest_result?: string | null;
  created_at: string;
}

export interface ValidationTask {
  id: number;
  assessment_id: number;
  finding_id: number;
  level: number;
  status: string;
  verdict?: string | null;
  notes?: string | null;
  started_at?: string | null;
  finished_at?: string | null;
}

export interface ReportRecord {
  id: number;
  assessment_id: number;
  report_type: string;
  file_path: string;
  file_sha256: string;
  file_size: number;
  status: string;
  generated_by?: number | null;
  generated_at: string;
}

export interface AuditEntry {
  id: number;
  user_id?: number | null;
  user?: string | null;
  action: string;
  assessment_id?: number | null;
  object_type?: string | null;
  object_id?: number | null;
  result?: string | null;
  detail?: string | null;
  ip_address?: string | null;
  timestamp: string;
}

export interface DashboardData {
  cards: {
    total_assets: number;
    open_vulnerabilities: number;
    critical_findings: number;
    high_findings: number;
    attack_paths: number;
    validated_findings: number;
    max_risk: number;
    remediation_progress: number;
    total_findings: number;
    assessments: number;
    active_assessments: number;
    completed_assessments: number;
  };
  charts: {
    severity_distribution: { key: string; value: number }[];
    risk_by_asset: { label: string; value: number; criticality: number }[];
    vulnerability_trend: { date: string; findings: number }[];
    remediation_status: { key: string; value: number }[];
  };
  recent_assessments: {
    id: number;
    name: string;
    status: string;
    progress: number;
    stage: string;
    created_at: string;
  }[];
}

export interface AssessmentOverview {
  assessment: Assessment;
  assets: number;
  services: number;
  findings: number;
  severity: Record<string, number>;
  open_findings: number;
  attack_paths: number;
  max_risk: number;
  remediation_progress: number;
  validated_findings: number;
}

export interface PrioritizationItem {
  rank: number;
  finding_id: number;
  title: string;
  risk: number;
  severity: string;
  priority: string;
  deadline?: string | null;
  asset?: string | null;
  status: string;
  breakdown?: Record<string, unknown>;
}

export interface RevisionChartPoint {
  date: string;
  open: number;
  high: number;
  critical: number;
  total: number;
}