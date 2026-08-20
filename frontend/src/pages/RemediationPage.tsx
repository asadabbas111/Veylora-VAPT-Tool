import React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useParams, Link } from "react-router-dom";
import { ClipboardList, FlaskConical, RefreshCw, CheckCircle2 } from "lucide-react";
import { api, apiError } from "../lib/api";
import { PageHeader, StatusBadge, RiskGauge, EmptyState, PageSpinner } from "../components/badges";
import { StatCard, Spinner } from "../components/ui";
import type { RemediationTask } from "../lib/types";
import { fmtDate } from "../lib/utils";

const FLOW: Record<string, string[]> = {
  open: [],
  acknowledged: [],
  in_progress: [],
  fixed: ["verified", "retest_required"],
  retest_required: [],
  verified: [],
  false_positive: [],
  risk_accepted: [],
};

export default function RemediationPage() {
  const { id } = useParams();
  const aid = Number(id);
  const qc = useQueryClient();
  const [error, setError] = React.useState("");

  const { data: tasks, isLoading } = useQuery({
    queryKey: ["remediation", aid],
    queryFn: async () => (await api.get<RemediationTask[]>("/remediation", { params: { assessment_id: aid } })).data,
  });

  const { data: progress } = useQuery({
    queryKey: ["remediation-progress", aid],
    queryFn: async () => (await api.get<any>("/remediation/progress", { params: { assessment_id: aid } })).data,
  });

  const updateStatus = useMutation({
    mutationFn: ({ taskId, status }: { taskId: number; status: string }) =>
      api.post(`/remediation/${taskId}/status`, { status }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["remediation", aid] }),
    onError: (e) => setError(apiError(e)),
  });

  const retest = useMutation({
    mutationFn: (taskId: number) => api.post(`/remediation/${taskId}/retest`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["remediation", aid] }),
    onError: (e) => setError(apiError(e)),
  });

  if (isLoading) return <PageSpinner />;

  return (
    <div>
      <PageHeader
        title="Remediation"
        subtitle="Track fixes and validate they reduce risk with authorized re-tests."
      />

      {error && (
        <div className="mb-4 rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-700">{error}</div>
      )}

      {progress && (
        <div className="mb-6 grid grid-cols-2 gap-4 md:grid-cols-4">
          <StatCard label="Tasks" value={progress.total} icon={<ClipboardList size={18} />} />
          <StatCard label="Completed" value={progress.done} icon={<CheckCircle2 size={18} />} tone="green" />
          <StatCard label="Progress" value={`${progress.progress}%`} icon={<RefreshCw size={18} />} tone="sky" />
          <StatCard label="Still Open" value={progress.total - progress.done} icon={<ClipboardList size={18} />} tone="red" />
        </div>
      )}

      {!tasks?.length ? (
        <EmptyState
          icon={<ClipboardList size={40} />}
          title="No remediation tasks"
          subtitle="Open a finding and create a remediation task, or run a fresh scan."
        />
      ) : (
        <div className="space-y-3">
          {tasks.map((t) => {
            const before = t.retest_before_score;
            const after = t.retest_after_score;
            const improved = after != null && before != null && after < before;
            return (
              <div key={t.id} className="card p-5">
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-bold text-ink">Finding #{t.finding_id}</span>
                      <Link to={`/assessments/${aid}/findings/${t.finding_id}`} className="text-xs text-brand-700 hover:underline">
                        view finding →
                      </Link>
                      <StatusBadge status={t.status} />
                    </div>
                    <p className="mt-1.5 text-sm text-ink-soft">{t.remediation_plan}</p>
                    <div className="mt-1.5 flex flex-wrap gap-3 text-xs text-ink-faint">
                      {t.assignee_name && <span>Assigned to <strong className="text-ink">{t.assignee_name}</strong></span>}
                      {t.deadline && <span>Deadline: {fmtDate(t.deadline)}</span>}
                      <span>Created: {fmtDate(t.created_at)}</span>
                    </div>
                  </div>
                  <div className="flex flex-col items-end">
                    {before != null && (
                      <div className="text-sm">
                        <span className="text-ink-faint">risk </span>
                        <RiskGauge score={before} />
                        {after != null && (
                          <>
                            <span className="mx-1.5 text-ink-faint">→</span>
                            <span className={`font-bold ${improved ? "text-emerald-600" : "text-red-500"}`}>{after.toFixed(1)}</span>
                          </>
                        )}
                      </div>
                    )}
                    {t.retest_result && (
                      <span className={`mt-1 rounded px-2 py-0.5 text-[11px] font-semibold ${
                        t.retest_result === "fixed" ? "bg-emerald-50 text-emerald-700" : "bg-red-50 text-red-600"
                      }`}>
                        {t.retest_result === "fixed" ? "Fix verified" : "Not fixed"}
                      </span>
                    )}
                  </div>
                </div>
                <div className="mt-4 flex flex-wrap gap-2">
                  {t.status !== "fixed" && t.status !== "verified" && (
                    <button className="btn-secondary text-xs" onClick={() => updateStatus.mutate({ taskId: t.id, status: "fixed" })}>
                      <CheckCircle2 size={14} /> Mark fixed
                    </button>
                  )}
                  {t.status === "fixed" && (
                    <button className="btn-primary text-xs" onClick={() => retest.mutate(t.id)} disabled={retest.isPending}>
                      {retest.isPending ? <Spinner className="h-3.5 w-3.5 text-white" /> : <FlaskConical size={14} />} Authorize re-test
                    </button>
                  )}
                  {t.status === "verified" && <span className="text-xs font-medium text-emerald-600">Remediation verified ✓</span>}
                  {!["verified", "false_positive", "risk_accepted"].includes(t.status) && t.status !== "fixed" && (
                    <>
                      <button className="btn-secondary text-xs" onClick={() => updateStatus.mutate({ taskId: t.id, status: "in_progress" })}>In progress</button>
                      <button className="btn-secondary text-xs" onClick={() => updateStatus.mutate({ taskId: t.id, status: "risk_accepted" })}>Accept risk</button>
                      <button className="btn-secondary text-xs" onClick={() => updateStatus.mutate({ taskId: t.id, status: "false_positive" })}>False positive</button>
                    </>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}