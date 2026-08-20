export const SEVERITY_COLOR: Record<string, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-amber-400",
  low: "bg-sky-400",
  info: "bg-slate-400",
};

export const SEVERITY_TEXT: Record<string, string> = {
  critical: "text-red-600 bg-red-50 border-red-200",
  high: "text-orange-600 bg-orange-50 border-orange-200",
  medium: "text-amber-700 bg-amber-50 border-amber-200",
  low: "text-sky-700 bg-sky-50 border-sky-200",
  info: "text-slate-500 bg-slate-50 border-slate-200",
};

export const STATUS_COLOR: Record<string, string> = {
  running: "bg-brand-100 border-brand-200 text-brand-700",
  pending: "bg-slate-100 border-slate-200 text-slate-600",
  completed: "bg-emerald-50 border-emerald-200 text-emerald-700",
  failed: "bg-red-50 border-red-200 text-red-600",
  cancelled: "bg-slate-100 border-slate-200 text-slate-500",
  paused: "bg-amber-50 border-amber-200 text-amber-700",
  open: "bg-red-50 border-red-200 text-red-600",
  acknowledged: "bg-orange-50 border-orange-200 text-orange-600",
  in_progress: "bg-brand-100 border-brand-200 text-brand-700",
  fixed: "bg-emerald-50 border-emerald-200 text-emerald-700",
  retest_required: "bg-amber-50 border-amber-200 text-amber-700",
  verified: "bg-emerald-50 border-emerald-200 text-emerald-700",
  false_positive: "bg-slate-100 border-slate-200 text-slate-500",
  risk_accepted: "bg-violet-50 border-violet-200 text-violet-700",
  draft: "bg-slate-100 border-slate-200 text-slate-600",
  scoping: "bg-brand-100 border-brand-200 text-brand-700",
  confirmed: "bg-emerald-50 border-emerald-200 text-emerald-700",
  refuted: "bg-slate-100 border-slate-200 text-slate-500",
  inconclusive: "bg-amber-50 border-amber-200 text-amber-700",
  stopped: "bg-slate-100 border-slate-200 text-slate-500",
  approved: "bg-emerald-50 border-emerald-200 text-emerald-700",
  blocked: "bg-red-50 border-red-200 text-red-600",
  success: "bg-emerald-50 border-emerald-200 text-emerald-700",
  created: "bg-brand-100 border-brand-200 text-brand-700",
  asset_discovery: "bg-brand-100 border-brand-200 text-brand-700",
  vulnerability_scan: "bg-brand-100 border-brand-200 text-brand-700",
  risk_calculation: "bg-brand-100 border-brand-200 text-brand-700",
  attack_path_analysis: "bg-brand-100 border-brand-200 text-brand-700",
  ai_analysis: "bg-brand-100 border-brand-200 text-brand-700",
  report_generation: "bg-brand-100 border-brand-200 text-brand-700",
  service_enumeration: "bg-brand-100 border-brand-200 text-brand-700",
  full: "bg-brand-100 border-brand-200 text-brand-700",
};

export function severityText(s: string): string {
  return SEVERITY_TEXT[s] ?? SEVERITY_TEXT.info;
}

export function statusText(s: string): string {
  return STATUS_COLOR[s] ?? "bg-slate-100 border-slate-200 text-slate-600";
}

export const fmtNum = (n: number) => n.toLocaleString();

export function fmtDate(iso?: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

export function fmtDateTime(iso?: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function timeAgo(iso?: string | null): string {
  if (!iso) return "—";
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function riskBand(score: number): { label: string; text: string } {
  if (score >= 80) return { label: "Critical", text: SEVERITY_TEXT.critical };
  if (score >= 60) return { label: "High", text: SEVERITY_TEXT.high };
  if (score >= 40) return { label: "Medium", text: SEVERITY_TEXT.medium };
  if (score >= 20) return { label: "Low", text: SEVERITY_TEXT.low };
  return { label: "Info", text: SEVERITY_TEXT.info };
}

export function initials(name?: string): string {
  if (!name) return "?";
  return name
    .split(/\s+/)
    .map((p) => p[0])
    .slice(0, 2)
    .join("")
    .toUpperCase();
}