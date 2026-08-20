import React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useParams } from "react-router-dom";
import { FileText, Download, FilePlus2, Trash2, CheckSquare } from "lucide-react";
import { api, apiError } from "../lib/api";
import { PageHeader, EmptyState, PageSpinner } from "../components/badges";
import { Badge, Spinner } from "../components/ui";
import type { ReportRecord } from "../lib/types";
import { fmtDateTime } from "../lib/utils";

export default function ReportsPage() {
  const { id } = useParams();
  const aid = Number(id);
  const qc = useQueryClient();
  const [selected, setSelected] = React.useState<Set<number>>(new Set());
  const [error, setError] = React.useState("");
  const [running, setRunning] = React.useState(false);

  const { data: reports, isLoading } = useQuery({
    queryKey: ["reports", aid],
    queryFn: async () => (await api.get<ReportRecord[]>("/reports", { params: { assessment_id: aid } })).data,
    refetchInterval: 4000,
  });

  const invalidate = () => qc.invalidateQueries({ queryKey: ["reports", aid] });

  const generate = useMutation({
    mutationFn: async () => {
      setRunning(true);
      try {
        await api.post(`/reports/generate/${aid}`);
        setTimeout(() => invalidate(), 1500);
        setRunning(false);
      } catch (e) {
        setRunning(false);
        throw e;
      }
    },
    onError: (e) => setError(apiError(e)),
  });

  const download = useMutation({
    mutationFn: async (r: ReportRecord) => {
      const res = await api.get(`/reports/download/${r.id}`, { responseType: "blob", timeout: 60000 });
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const a = document.createElement("a");
      a.href = url;
      a.download = `report_${r.assessment_id}_${r.id}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    },
    onError: (e) => setError(apiError(e)),
  });

  const remove = useMutation({
    mutationFn: async (ids: number[]) => {
      if (ids.length === 1) {
        await api.delete(`/reports/${ids[0]}`);
      } else {
        await api.post("/reports/bulk-delete", { ids });
      }
    },
    onSuccess: () => {
      setSelected(new Set());
      invalidate();
    },
    onError: (e) => setError(apiError(e)),
  });

  const ids = (reports ?? []).map((r) => r.id);
  const allSelected = ids.length > 0 && ids.every((id) => selected.has(id));

  const toggle = (id: number) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const toggleAll = () => setSelected(allSelected ? new Set() : new Set(ids));

  const confirmDelete = (ids: number[], label: string) => {
    if (window.confirm(`Delete ${label}? This cannot be undone.`)) remove.mutate(ids);
  };

  return (
    <div>
      <PageHeader
        title="Reports"
        subtitle="Formal deliverables generated from findings, risk and attack paths."
        actions={
          <div className="flex items-center gap-2">
            {selected.size > 0 && (
              <div className="flex items-center gap-2 rounded-lg bg-red-50 px-3 py-1.5 ring-1 ring-red-200">
                <span className="text-sm font-semibold text-red-700">{selected.size} selected</span>
                <button
                  className="btn-danger"
                  onClick={() => confirmDelete([...selected], `${selected.size} selected reports`)}
                  disabled={remove.isPending}
                >
                  <Trash2 size={15} /> Delete selected
                </button>
              </div>
            )}
            <button className="btn-primary" onClick={() => generate.mutate()} disabled={running}>
              {running ? <Spinner className="h-4 w-4 text-white" /> : <FilePlus2 size={16} />} Generate PDF report
            </button>
          </div>
        }
      />

      {error && <div className="mb-4 rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-700">{error}</div>}

      {isLoading ? (
        <PageSpinner />
      ) : !reports?.length ? (
        <EmptyState icon={<FileText size={40} />} title="No reports yet" subtitle="Generate a professional PDF report of this assessment." />
      ) : (
        <div>
          <div className="mb-3 flex items-center justify-between">
            <button
              className="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm font-medium text-ink-soft hover:bg-slate-50"
              onClick={toggleAll}
            >
              <CheckSquare size={15} className={allSelected ? "text-brand-600" : ""} />
              {allSelected ? "Deselect all" : "Select all"}
            </button>
            <span className="text-xs text-ink-faint">{reports.length} reports</span>
          </div>
          <div className="space-y-3">
            {reports.map((r) => {
              const checked = selected.has(r.id);
              return (
                <div
                  key={r.id}
                  className={`card flex flex-wrap items-center justify-between gap-4 p-5 ${
                    checked ? "ring-2 ring-brand-400 border-brand-300" : ""
                  }`}
                >
                  <div className="flex items-center gap-4">
                    <label className="flex cursor-pointer items-center">
                      <input
                        type="checkbox"
                        className="h-4 w-4 accent-brand-600"
                        checked={checked}
                        onChange={() => toggle(r.id)}
                      />
                    </label>
                    <div className="flex h-11 w-11 items-center justify-center rounded-lg bg-red-50 text-red-500 ring-1 ring-red-100">
                      <FileText size={20} />
                    </div>
                    <div>
                      <p className="text-sm font-bold text-ink capitalize">{(r.report_type || "full").replace(/_/g, " ")} report</p>
                      <p className="mt-0.5 text-xs text-ink-soft">
                        Generated {fmtDateTime(r.generated_at)} · {r.file_size} bytes
                      </p>
                      <p className="mt-0.5 font-mono text-[10px] text-ink-faint">SHA-256 {r.file_sha256}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <button className="btn-primary" onClick={() => download.mutate(r)} disabled={download.isPending}>
                      {download.isPending ? <Spinner className="h-4 w-4 text-white" /> : <Download size={16} />} Download
                    </button>
                    <button
                      title="Delete report"
                      onClick={() => confirmDelete([r.id], "this report")}
                      className="rounded-md p-2 text-ink-faint hover:bg-red-50 hover:text-red-600"
                    >
                      <Trash2 size={16} />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      <div className="card mt-6 p-5 text-sm text-ink-soft">
        <Badge tone="sky">Report contents</Badge>
        <p className="mt-2">
          Cover · Executive summary · Authorized scope · Methodology · Asset inventory ·
          Risk summary · Web application findings · Findings by severity (CVSS + affected location) ·
          Attack paths · MITRE ATT&CK mapping · Evidence · Remediation plan · Timeline.
        </p>
      </div>
    </div>
  );
}