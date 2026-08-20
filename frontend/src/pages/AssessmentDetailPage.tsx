import React from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useParams, Link } from "react-router-dom";
import {
  Play, Pause, RotateCcw, Ban, Server, Bug, GitBranch, CheckCircle2, ShieldAlert, Terminal, RefreshCw, FileText,
} from "lucide-react";
import { api, apiError } from "../lib/api";
import { StatCard, Spinner } from "../components/ui";
import { PageHeader, StatusBadge, SeverityBadge, EmptyState, PageSpinner } from "../components/badges";
import type { AssessmentDetail, Job, AssessmentOverview } from "../lib/types";
import { fmtDateTime, timeAgo } from "../lib/utils";

const STAGE_BTN: Record<string, string> = {
  asset_discovery: "Asset Discovery",
  vulnerability_scan: "Vulnerability Scan",
  risk_calculation: "Risk Calculation",
  attack_path_analysis: "Attack Paths",
  ai_analysis: "AI Analysis",
  report_generation: "Report",
  full: "Full Workflow",
};

export default function AssessmentDetailPage() {
  const { id } = useParams();
  const aid = Number(id);
  const qc = useQueryClient();

  const { data: detail } = useQuery({
    queryKey: ["assessment", aid],
    queryFn: async () => (await api.get<AssessmentDetail>(`/assessments/${aid}`)).data,
  });

  const { data: overview } = useQuery({
    queryKey: ["overview", aid],
    queryFn: async () => (await api.get<AssessmentOverview>(`/assessments/${aid}/overview`)).data,
    refetchInterval: 4000,
  });

  const { data: jobs } = useQuery({
    queryKey: ["jobs", aid],
    queryFn: async () => (await api.get<Job[]>(`/assessments/${aid}/jobs`)).data,
    refetchInterval: 3000,
  });

  if (!detail && !overview) return <PageSpinner />;

  const o = overview;
  const sev = o?.severity ?? {};

  const run = async (stage: string) => {
    try {
      await api.post(`/assessments/${aid}/workflow`, { stage, adapters: [] });
      qc.invalidateQueries({ queryKey: ["jobs", aid] });
    } catch (e) {
      alert(apiError(e));
    }
  };

  return (
    <div>
      <PageHeader
        title={detail?.name ?? "Assessment"}
        subtitle={
          detail
            ? `${detail.assessment_type.replace(/_/g, " ")} · created ${timeAgo(detail.created_at)} · validation level ${detail.validation_level}`
            : ""
        }
        actions={
          <>
            <button className="btn-secondary" onClick={() => run("full")}>
              <Play size={16} /> Run all
            </button>
            <button className="btn-secondary" onClick={() => run("vulnerability_scan")}>
              <RefreshCw size={16} /> Rescan
            </button>
          </>
        }
      />

      {o && (
        <div className="grid grid-cols-2 gap-4 md:grid-cols-4 xl:grid-cols-7">
          <StatCard label="Status" value={<StatusBadge status={o.assessment.status} />} icon={<ShieldAlert size={18} />} />
          <StatCard label="Assets" value={o.assets} icon={<Server size={18} />} sub={`${o.services} services`} />
          <StatCard label="Findings" value={o.findings} icon={<Bug size={18} />} sub={`${o.open_findings} open`} tone="red" />
          <StatCard label="Critical" value={sev.critical ?? 0} icon={<ShieldAlert size={18} />} tone="red" sub={`${sev.high ?? 0} high`} />
          <StatCard label="Attack Paths" value={o.attack_paths} icon={<GitBranch size={18} />} tone="violet" />
          <StatCard label="Max Risk" value={o.max_risk} icon={<ShieldAlert size={18} />} tone="amber" sub={`${o.validated_findings} validated`} />
          <StatCard label="Remediation" value={`${o.remediation_progress}%`} icon={<CheckCircle2 size={18} />} tone="green" sub={`${o.findings} findings`} />
        </div>
      )}

      {/* Scope & Targets */}
      {detail && (
        <div className="mt-6 grid grid-cols-1 gap-6 xl:grid-cols-2">
          <div className="card p-5">
            <h3 className="mb-3 text-sm font-bold text-ink">Authorized Scope</h3>
            {detail.scopes.length === 0 ? (
              <p className="text-sm text-ink-faint">No scope defined yet.</p>
            ) : (
              <ul className="space-y-2">
                {detail.scopes.map((s) => (
                  <li key={s.id} className="flex items-center justify-between rounded-lg bg-slate-50 px-3 py-2.5">
                    <code className="font-mono text-sm font-semibold text-ink">{s.target}</code>
                    <span className="rounded bg-brand-100 px-2 py-0.5 text-[11px] font-semibold text-brand-700">{s.target_type}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
          <div className="card p-5">
            <h3 className="mb-3 text-sm font-bold text-ink">In-scope Targets</h3>
            {detail.targets.length === 0 ? (
              <p className="text-sm text-ink-faint">No targets added yet.</p>
            ) : (
              <ul className="space-y-2">
                {detail.targets.map((t) => (
                  <li key={t.id} className="flex items-center justify-between rounded-lg bg-slate-50 px-3 py-2.5">
                    <div>
                      <code className="font-mono text-sm font-semibold text-ink">{t.target}</code>
                      <p className="text-[11px] text-ink-faint">{t.validation_note}</p>
                    </div>
                    {t.in_scope ? (
                      <span className="rounded bg-emerald-50 px-2 py-0.5 text-[11px] font-semibold text-emerald-700">verified</span>
                    ) : (
                      <span className="rounded bg-red-50 px-2 py-0.5 text-[11px] font-semibold text-red-600">blocked</span>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}

      {/* Stage runners */}
      <div className="card mt-6 p-5">
        <h3 className="mb-3 flex items-center gap-2 text-sm font-bold text-ink">
          <Terminal size={16} className="text-brand-600" /> Run Workflow Stage
        </h3>
        <div className="flex flex-wrap gap-2">
          {Object.entries(STAGE_BTN).map(([stage, label]) => (
            <button key={stage} className="btn-secondary" onClick={() => run(stage)}>
              {stage === "vulnerability_scan" ? <Play size={14} /> : stage === "report_generation" ? <FileText size={14} /> : <RefreshCw size={14} />}
              {label}
            </button>
          ))}
          <button className="btn-secondary" onClick={async () => { try { await api.post(`/assessments/${aid}/pause`); } catch {} }}>
            <Pause size={14} /> Pause
          </button>
          <button className="btn-secondary" onClick={async () => { try { await api.post(`/assessments/${aid}/resume`); } catch {} }}>
            <RotateCcw size={14} /> Resume
          </button>
          <button className="btn-danger" onClick={async () => { try { await api.post(`/assessments/${aid}/cancel`); } catch {} }}>
            <Ban size={14} /> Cancel
          </button>
        </div>
      </div>

      {/* Jobs timeline */}
      <div className="card mt-6 overflow-hidden">
        <div className="px-5 py-4">
          <h3 className="text-sm font-bold text-ink">Workflow Jobs</h3>
        </div>
        {jobs && jobs.length > 0 ? (
          <div className="divide-y divide-slate-100">
            {jobs.map((j) => (
              <div key={j.id} className="px-5 py-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-semibold text-ink capitalize">{j.task_type.replace(/_/g, " ")}</span>
                    <StatusBadge status={j.status} />
                    {j.error && <span className="text-xs text-red-600">{j.error}</span>}
                  </div>
                  <div className="flex items-center gap-3 text-xs text-ink-faint">
                    <span>#{j.id}</span>
                    <span>{j.started_at ? `started ${timeAgo(j.started_at)}` : ""}</span>
                    <span>{j.finished_at ? `· finished ${timeAgo(j.finished_at)}` : ""}</span>
                    <span className="font-semibold text-brand-700">{j.progress}%</span>
                  </div>
                </div>
                <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-slate-200">
                  <div className="h-full rounded-full bg-brand-500 transition-all" style={{ width: `${j.progress}%` }} />
                </div>
                {j.log && (
                  <pre className="mt-2 max-h-24 overflow-y-auto whitespace-pre-wrap rounded bg-slate-50 p-2 font-mono text-[11px] leading-relaxed text-ink-soft">
                    {j.log}
                  </pre>
                )}
              </div>
            ))}
          </div>
        ) : (
          <div className="p-5">
            <EmptyState icon={<Terminal size={36} />} title="No jobs yet" subtitle="Run the full workflow or a single stage to begin." />
          </div>
        )}
      </div>
    </div>
  );
}