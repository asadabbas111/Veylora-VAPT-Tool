import React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Plus, Radar, ClipboardList, Clock, Trash2, CheckSquare } from "lucide-react";
import { api, apiError } from "../lib/api";
import { PageHeader, StatusBadge, EmptyState, PageSpinner } from "../components/badges";
import { Badge } from "../components/ui";
import type { Assessment } from "../lib/types";
import { fmtDate } from "../lib/utils";

const TYPE_LABEL: Record<string, string> = {
  vulnerability_assessment: "Vulnerability Assessment",
  penetration_test: "Penetration Test",
  red_team: "Red Team Exercise",
  security_review: "Security Review",
};

export default function AssessmentsPage() {
  const qc = useQueryClient();
  const [selected, setSelected] = React.useState<Set<number>>(new Set());
  const [error, setError] = React.useState("");

  const { data, isLoading } = useQuery({
    queryKey: ["assessments"],
    queryFn: async () => (await api.get<Assessment[]>("/assessments")).data,
  });

  const invalidate = () => qc.invalidateQueries({ queryKey: ["assessments"] });

  const remove = useMutation({
    mutationFn: async (ids: number[]) => {
      if (ids.length === 1) {
        await api.delete(`/assessments/${ids[0]}`);
      } else {
        await api.post("/assessments/bulk-delete", { ids });
      }
    },
    onSuccess: () => {
      setSelected(new Set());
      invalidate();
    },
    onError: (e) => setError(apiError(e)),
  });

  const ids = (data ?? []).map((a) => a.id);
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
        title="Assessments"
        subtitle="Authorized engagement portfolios — every target is validated against its scope."
        actions={
          <>
            {selected.size > 0 && (
              <div className="flex items-center gap-2 rounded-lg bg-red-50 px-3 py-1.5 ring-1 ring-red-200">
                <span className="text-sm font-semibold text-red-700">{selected.size} selected</span>
                <button
                  className="btn-danger"
                  onClick={() =>
                    confirmDelete([...selected], `${selected.size} selected assessments`)
                  }
                  disabled={remove.isPending}
                >
                  <Trash2 size={15} /> Delete selected
                </button>
              </div>
            )}
            <Link to="/assessments/new" className="btn-primary">
              <Plus size={16} /> New Assessment
            </Link>
          </>
        }
      />

      {error && <div className="mb-4 rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-700">{error}</div>}

      {isLoading ? (
        <PageSpinner />
      ) : !data || data.length === 0 ? (
        <EmptyState
          icon={<Radar size={40} />}
          title="No assessments yet"
          subtitle="Create an assessment, define an authorized scope, add in-scope targets and run the automated workflow."
          action={
            <Link to="/assessments/new" className="btn-primary">
              <Plus size={16} /> Create Assessment
            </Link>
          }
        />
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
            <span className="text-xs text-ink-faint">{data.length} assessments</span>
          </div>
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
            {data.map((a) => {
              const checked = selected.has(a.id);
              return (
                <div
                  key={a.id}
                  className={`card group relative p-5 transition hover:shadow-lift hover:border-brand-200 ${
                    checked ? "ring-2 ring-brand-400 border-brand-300" : ""
                  }`}
                >
                  <div className="flex items-start justify-between">
                    <label
                      className="flex h-11 w-11 cursor-pointer items-center justify-center rounded-lg bg-brand-50 text-brand-600 ring-1 ring-brand-100"
                      onClick={(e) => e.preventDefault()}
                    >
                      <input
                        type="checkbox"
                        className="h-4 w-4 accent-brand-600"
                        checked={checked}
                        onChange={() => toggle(a.id)}
                      />
                    </label>
                    <StatusBadge status={a.status} />
                  </div>
                  <Link to={`/assessments/${a.id}`} className="block">
                    <h3 className="mt-4 text-base font-bold text-ink group-hover:text-brand-700">{a.name}</h3>
                    <p className="mt-1 line-clamp-2 text-sm text-ink-soft">
                      {TYPE_LABEL[a.assessment_type] ?? a.assessment_type}
                      {a.client_name ? ` for ${a.client_name}` : ""}
                    </p>
                    <div className="mt-4 flex items-center justify-between text-xs text-ink-faint">
                      <span className="inline-flex items-center gap-1">
                        <Clock size={13} /> {fmtDate(a.created_at)}
                      </span>
                      <span className="inline-flex items-center gap-1.5 font-semibold text-ink-soft capitalize">
                        {a.stage.replace(/_/g, " ")}
                      </span>
                    </div>
                    <div className="mt-3 flex items-center gap-2">
                      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-slate-200">
                        <div className="h-full rounded-full bg-brand-500" style={{ width: `${a.progress}%` }} />
                      </div>
                      <span className="text-xs font-semibold text-brand-700">{a.progress}%</span>
                    </div>
                  </Link>
                  <button
                    title="Delete assessment"
                    onClick={(e) => {
                      e.preventDefault();
                      e.stopPropagation();
                      confirmDelete([a.id], a.name);
                    }}
                    className="absolute right-3 top-3 z-10 rounded-md p-1.5 text-ink-faint opacity-0 transition group-hover:opacity-100 hover:bg-red-50 hover:text-red-600"
                  >
                    <Trash2 size={16} />
                  </button>
                </div>
              );
            })}
          </div>
        </div>
      )}

      <div className="card mt-6 p-5 text-sm text-ink-soft">
        <Badge tone="sky">About scans</Badge>
        <p className="mt-2">
          Scans run the full workflow: scope validation → asset discovery → service enumeration → vulnerability
          scanning → risk scoring → attack-path analysis → AI analysis → validation → reporting. Larger scopes and
          deeper validation take longer because each target and finding is processed individually.
        </p>
      </div>
    </div>
  );
}