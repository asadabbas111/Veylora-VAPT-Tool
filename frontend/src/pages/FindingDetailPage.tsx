import React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useParams, Link } from "react-router-dom";
import {
  ArrowLeft, ShieldCheck, FileSearch, Cpu, FlaskConical, CheckCircle2, AlertTriangle, Hash, Trophy, XCircle, ListOrdered,
} from "lucide-react";
import { api, apiError } from "../lib/api";
import { PageHeader, SeverityBadge, StatusBadge, PriorityPill, RiskGauge, EmptyState, PageSpinner } from "../components/badges";
import { Spinner, Badge } from "../components/ui";
import type { FindingDetail, AIAnalysis, ValidationTask, RemediationTask } from "../lib/types";
import { fmtDateTime, fmtDate } from "../lib/utils";

export default function FindingDetailPage() {
  const { id, findingId } = useParams();
  const aid = Number(id);
  const fid = Number(findingId);
  const qc = useQueryClient();
  const [error, setError] = React.useState("");

  const { data: f, isLoading } = useQuery({
    queryKey: ["finding", fid],
    queryFn: async () => (await api.get<FindingDetail>(`/findings/${fid}`)).data,
  });

  const { data: analyses } = useQuery({
    queryKey: ["analyses", fid],
    queryFn: async () => (await api.get<AIAnalysis[]>(`/findings/${fid}/analyses`)).data,
  });

  const { data: validationTasks } = useQuery({
    queryKey: ["validation-tasks", fid],
    queryFn: async () => (await api.get<ValidationTask[]>(`/findings/${fid}/validation-tasks`)).data,
    refetchInterval: 2500,
  });

  const { data: attackPaths } = useQuery({
    queryKey: ["finding-paths", fid],
    queryFn: async () => (await api.get<{ id: number; name: string; path_length: number; cumulative_risk: number; steps: string[] }[]>(`/findings/${fid}/attack-paths`)).data,
  });

  const analyze = useMutation({
    mutationFn: () => api.post(`/ai/analyze/${fid}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["analyses", fid] });
      qc.invalidateQueries({ queryKey: ["finding", fid] });
    },
    onError: (e) => setError(apiError(e)),
  });

  const requestValidation = useMutation({
    mutationFn: (level: number) => api.post(`/validation/request/${fid}`, { level }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["validation-tasks", fid] }),
    onError: (e) => setError(apiError(e)),
  });

  const setStatus = useMutation({
    mutationFn: (status: string) => api.patch(`/findings/${fid}`, { status }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["finding", fid] }),
  });

  if (isLoading || !f) return <PageSpinner />;

  const latestVt = validationTasks?.[0];

  return (
    <div>
      <PageHeader
        title={f.title}
        subtitle={<Link to={`/assessments/${aid}/findings`} className="text-brand-700 underline-offset-2 hover:underline"><ArrowLeft size={14} className="mr-1 inline" /> Back to findings</Link>}
        actions={
          <>
            <StatusBadge status={f.status} />
            <div className="flex gap-2">
              <select className="input w-40" value={f.status} onChange={(e) => setStatus.mutate(e.target.value)}>
                {["open", "acknowledged", "in_progress", "fixed", "retest_required", "verified", "false_positive", "risk_accepted"].map((s) => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
              <button className="btn-primary" onClick={() => analyze.mutate()} disabled={analyze.isPending}>
                {analyze.isPending ? <Spinner className="h-4 w-4 text-white" /> : <Cpu size={16} />} AI Analysis
              </button>
            </div>
          </>
        }
      />

      {error && (
        <div className="mb-4 flex items-center gap-2 rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-700">
          <AlertTriangle size={18} /> {error}
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        {/* Left: detail */}
        <div className="space-y-6 xl:col-span-2">
          <div className="card p-5">
            <div className="flex flex-wrap items-center gap-3">
              <SeverityBadge severity={f.severity} />
              <PriorityPill priority={f.ai_priority} />
              <div className="flex items-center gap-3">
                <RiskGauge score={f.risk_score} />
                <span className="text-xs text-ink-faint">risk score</span>
              </div>
              <Badge tone="sky"><Hash size={12} /> CVSS {f.cvss_score ?? "n/a"}</Badge>
              <Badge tone="green"><CheckCircle2 size={12} /> confidence {f.confidence}%</Badge>
            </div>

            <dl className="mt-5 grid grid-cols-1 gap-4 sm:grid-cols-2">
              {f.cve && (
                <div>
                  <dt className="text-xs font-semibold uppercase tracking-wide text-ink-faint">CVE</dt>
                  <dd className="mt-1 font-mono text-sm font-bold text-red-600">{f.cve}</dd>
                </div>
              )}
              {f.cwe && (
                <div>
                  <dt className="text-xs font-semibold uppercase tracking-wide text-ink-faint">CWE</dt>
                  <dd className="mt-1 font-mono text-sm text-ink">{f.cwe}</dd>
                </div>
              )}
              {f.affected_service && (
                <div>
                  <dt className="text-xs font-semibold uppercase tracking-wide text-ink-faint">Affected service</dt>
                  <dd className="mt-1 text-sm text-ink">{f.affected_service}</dd>
                </div>
              )}
              {f.affected_port && (
                <div>
                  <dt className="text-xs font-semibold uppercase tracking-wide text-ink-faint">Port</dt>
                  <dd className="mt-1 text-sm text-ink">:{f.affected_port}</dd>
                </div>
              )}
              <div>
                <dt className="text-xs font-semibold uppercase tracking-wide text-ink-faint">Source</dt>
                <dd className="mt-1 text-sm text-ink">{f.detection_source ?? "scan"}</dd>
              </div>
              <div>
                <dt className="text-xs font-semibold uppercase tracking-wide text-ink-faint">First seen</dt>
                <dd className="mt-1 text-sm text-ink">{fmtDateTime(f.first_seen)}</dd>
              </div>
            </dl>

            <div className="mt-6">
              <h3 className="text-sm font-bold text-ink">Description</h3>
              <p className="mt-1.5 whitespace-pre-wrap text-sm leading-relaxed text-ink-soft">{f.description || "No description."}</p>
            </div>

            {f.risk_breakdown && Object.keys(f.risk_breakdown).length > 0 && (
              <div className="mt-6">
                <h3 className="text-sm font-bold text-ink">Risk Breakdown</h3>
                <div className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-3">
                  {Object.entries(f.risk_breakdown).map(([k, v]) => (
                    <div key={k} className="rounded-lg bg-slate-50 px-3 py-2">
                      <p className="text-[11px] font-medium capitalize text-ink-faint">{k.replace(/_/g, " ")}</p>
                      <p className="text-sm font-bold text-ink">{typeof v === "number" ? v.toFixed(1) : String(v)}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {f.mitre_techniques.length > 0 && (
              <div className="mt-6">
                <h3 className="text-sm font-bold text-ink">MITRE ATT&CK</h3>
                <div className="mt-2 flex flex-wrap gap-2">
                  {f.mitre_techniques.map((t) => (
                    <span key={t.technique_id} className="rounded-lg border border-violet-200 bg-violet-50 px-2.5 py-1 text-xs text-violet-800">
                      <span className="font-bold">{t.technique_id}</span> {t.name}
                      <span className="ml-1 text-violet-500">· {t.tactic}</span>
                    </span>
                  ))}
                </div>
              </div>
            )}

            {f.evidence.length > 0 && (
              <div className="mt-6">
                <h3 className="text-sm font-bold text-ink">Evidence</h3>
                <ul className="mt-2 space-y-2">
                  {f.evidence.map((e) => (
                    <li key={e.id} className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-xs">
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-ink">{e.filename || e.category}</span>
                        <span className="font-mono text-ink-faint">{e.sha256.slice(0, 16)}…</span>
                      </div>
                      {e.content && <pre className="mt-2 overflow-x-auto whitespace-pre-wrap text-[11px] text-ink-soft">{e.content}</pre>}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {f.remediation && (
              <div className="mt-6 rounded-lg border border-emerald-200 bg-emerald-50/60 p-4">
                <h3 className="flex items-center gap-2 text-sm font-bold text-emerald-800">
                  <FlaskConical size={16} /> Remediation guidance
                </h3>
                <p className="mt-1.5 whitespace-pre-wrap text-sm leading-relaxed text-emerald-900">{f.remediation}</p>
              </div>
            )}
          </div>

          {/* Attack paths containing this finding */}
          <div className="card p-5">
            <h3 className="mb-3 flex items-center gap-2 text-sm font-bold text-ink">
              <ListOrdered size={16} className="text-violet-500" /> Attack Paths Involving This Vulnerability
            </h3>
            {!attackPaths?.length ? (
              <p className="text-sm text-ink-faint">Not part of any current attack path.</p>
            ) : (
              <div className="space-y-3">
                {attackPaths.map((p) => (
                  <div key={p.id} className="rounded-lg border border-violet-200 bg-violet-50/50 p-4">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-ink">{p.name}</span>
                      <span className="flex items-center gap-1 text-sm font-bold text-violet-700">
                        <Trophy size={14} /> {p.cumulative_risk.toFixed(1)}
                      </span>
                    </div>
                    <div className="mt-2 flex flex-wrap items-center gap-1.5 text-[11px]">
                      {p.steps.map((step, i) => (
                        <React.Fragment key={i}>
                          {i > 0 && <span className="text-ink-faint">→</span>}
                          <span className="rounded bg-white px-2 py-0.5 font-medium text-ink-soft shadow-sm">{step}</span>
                        </React.Fragment>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Right: AI + validation */}
        <div className="space-y-6">
          <div className="card overflow-hidden">
            <div className="border-b border-slate-200 bg-brand-50/60 px-5 py-3.5">
              <h3 className="flex items-center gap-2 text-sm font-bold text-ink">
                <Cpu size={16} className="text-brand-600" /> AI Analyst
              </h3>
            </div>
            {!analyses?.length ? (
              <div className="p-5">
                <EmptyState icon={<Cpu size={32} />} title="No AI analysis yet" subtitle="Generate an AI assessment of severity, priority and false-positive likelihood." />
              </div>
            ) : (
              <div className="divide-y divide-slate-100">
                {analyses.map((a) => (
                  <div key={a.id} className="p-5">
                    <div className="flex items-center gap-2">
                      <PriorityPill priority={a.priority} />
                      <SeverityBadge severity={a.severity ?? f.severity} />
                      <span className="ml-auto text-xs text-ink-faint">
                        {a.provider} {a.model ? `· ${a.model}` : ""}
                      </span>
                    </div>
                    {a.priority_deadline && (
                      <p className="mt-2 text-xs font-medium text-amber-700">Recommended action by {fmtDate(a.priority_deadline)}</p>
                    )}
                    {a.executive_summary && <p className="mt-2 text-sm leading-relaxed text-ink-soft">{a.executive_summary}</p>}
                    {a.technical_explanation && (
                      <details className="mt-3">
                        <summary className="cursor-pointer text-xs font-semibold text-brand-700">Technical explanation</summary>
                        <p className="mt-1.5 text-sm text-ink-soft">{a.technical_explanation}</p>
                      </details>
                    )}
                    {a.risk_explanation && (
                      <details className="mt-3">
                        <summary className="cursor-pointer text-xs font-semibold text-brand-700">Why this risk score</summary>
                        <p className="mt-1.5 text-sm text-ink-soft">{a.risk_explanation}</p>
                      </details>
                    )}
                    {a.false_positive_assessment && (
                      <div className="mt-3 rounded-lg bg-slate-50 p-3">
                        <p className="text-xs font-semibold text-ink">False-positive assessment</p>
                        <p className="mt-1 text-sm text-ink-soft">{a.false_positive_assessment}</p>
                        <p className="mt-1 text-xs text-ink-faint">Likelihood: {a.false_positive_likelihood}%</p>
                      </div>
                    )}
                    {a.recommended_remediation && (
                      <div className="mt-3 rounded-lg bg-emerald-50 p-3">
                        <p className="text-xs font-semibold text-emerald-800">Recommended remediation</p>
                        <p className="mt-1 whitespace-pre-wrap text-sm text-emerald-900">{a.recommended_remediation}</p>
                      </div>
                    )}
                    {Array.isArray(a.basis) && a.basis.length > 0 && (
                      <p className="mt-3 text-[11px] text-ink-faint">Basis: {a.basis.map((b) => (typeof b === "string" ? b : JSON.stringify(b))).join(" · ")}</p>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="card overflow-hidden">
            <div className="border-b border-slate-200 px-5 py-3.5">
              <h3 className="flex items-center gap-2 text-sm font-bold text-ink">
                <FlaskConical size={16} className="text-brand-600" /> Controlled Validation
              </h3>
            </div>
            <div className="p-5">
              <p className="text-xs text-ink-soft">
                Request an authorized PoC. Levels above 1 require admin approval and every run is audited.
              </p>
              <div className="mt-3 flex flex-wrap gap-2">
                {[0, 1, 2, 3].map((lv) => (
                  <button
                    key={lv}
                    className="btn-secondary text-xs"
                    disabled={latestVt?.status === "running"}
                    onClick={() => requestValidation.mutate(lv)}
                  >
                    Level {lv}
                  </button>
                ))}
              </div>
              {latestVt && (
                <div className="mt-4 rounded-lg border border-slate-200 bg-slate-50 p-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-ink">Task #{latestVt.id}</span>
                    <StatusBadge status={latestVt.status} />
                  </div>
                  <p className="mt-1.5 text-xs text-ink-soft">
                    Level {latestVt.level} · verdict: <span className="font-semibold text-ink">{latestVt.verdict ?? "pending"}</span>
                  </p>
                  {latestVt.verdict === "confirmed" && (
                    <p className="mt-1.5 flex items-start gap-1.5 text-xs text-emerald-700">
                      <XCircle size={13} className="mt-0.5 shrink-0" /> {latestVt.notes}
                    </p>
                  )}
                  {latestVt.verdict === "refuted" && (
                    <p className="mt-1.5 flex items-start gap-1.5 text-xs text-slate-500">
                      <XCircle size={13} className="mt-0.5 shrink-0" /> {latestVt.notes}
                    </p>
                  )}
                  {latestVt.notes && !latestVt.verdict && <p className="mt-1.5 text-xs text-ink-soft">{latestVt.notes}</p>}
                  {latestVt.status === "pending" && (
                    <p className="mt-2 text-[11px] text-amber-700">Awaiting admin approval.</p>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}