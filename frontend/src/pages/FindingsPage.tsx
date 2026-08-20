import React from "react";
import { useQuery } from "@tanstack/react-query";
import { useParams, Link } from "react-router-dom";
import { Bug, Search, ListFilter } from "lucide-react";
import { api } from "../lib/api";
import { PageHeader, SeverityBadge, StatusBadge, PriorityPill, RiskGauge, EmptyState, PageSpinner } from "../components/badges";
import type { Finding } from "../lib/types";
import { riskBand } from "../lib/utils";

export default function FindingsPage() {
  const { id } = useParams();
  const aid = Number(id);
  const [search, setSearch] = React.useState("");
  const [severity, setSeverity] = React.useState("");
  const [prioFilter, setPrioFilter] = React.useState("");

  const { data, isLoading } = useQuery({
    queryKey: ["findings", aid, severity, search],
    queryFn: async () =>
      (
        await api.get<{ items: Finding[]; total: number }>("/findings", {
          params: { assessment_id: aid, page_size: 200, severity: severity || undefined, search: search || undefined },
        })
      ).data,
  });

  const { data: aiMap } = useQuery({
    queryKey: ["ai-map", aid],
    queryFn: async () => {
      const { data } = await api.get<{ items: { finding_id: number; priority: string; deadline?: string | null }[] }>(
        "/ai/prioritization",
        { params: { assessment_id: aid } }
      );
      const map: Record<number, { priority: string; deadline?: string }> = {};
      for (const it of data.items ?? []) map[it.finding_id] = { priority: it.priority, deadline: it.deadline ?? undefined };
      return map;
    },
  });

  const items = (data?.items ?? []).filter((f) => {
    if (!prioFilter) return true;
    return (aiMap?.[f.id]?.priority ?? "") === prioFilter;
  });

  return (
    <div>
      <PageHeader
        title="Findings"
        subtitle={`${data?.total ?? 0} vulnerabilities identified. AI-ranked by business risk.`}
        actions={
          <div className="flex items-center gap-2">
            <div className="relative">
              <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-ink-faint" />
              <input className="input w-56 pl-9" placeholder="Search…" value={search} onChange={(e) => setSearch(e.target.value)} />
            </div>
            <div className="relative">
              <ListFilter size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-ink-faint" />
              <select className="input w-40 pl-9" value={severity} onChange={(e) => setSeverity(e.target.value)}>
                <option value="">All severities</option>
                {["critical", "high", "medium", "low", "info"].map((s) => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
            </div>
            <select className="input w-32" value={prioFilter} onChange={(e) => setPrioFilter(e.target.value)}>
              <option value="">All P</option>
              {["P1", "P2", "P3", "P4"].map((p) => (
                <option key={p} value={p}>{p}</option>
              ))}
            </select>
          </div>
        }
      />

      {isLoading ? (
        <PageSpinner />
      ) : !items.length ? (
        <EmptyState icon={<Bug size={40} />} title="No findings" subtitle="Run a vulnerability scan to discover issues." />
      ) : (
        <div className="card overflow-hidden">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-50 text-xs uppercase tracking-wider text-ink-faint">
              <tr>
                <th className="px-5 py-3 font-semibold">Finding</th>
                <th className="px-4 py-3 font-semibold">Severity</th>
                <th className="px-4 py-3 font-semibold">Risk</th>
                <th className="px-4 py-3 font-semibold">AI Priority</th>
                <th className="px-4 py-3 font-semibold">CVSS</th>
                <th className="px-4 py-3 font-semibold">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {items.map((f) => {
                const band = riskBand(f.risk_score);
                return (
                  <tr key={f.id} className="hover:bg-slate-50/60">
                    <td className="px-5 py-3">
                      <Link to={`/assessments/${aid}/findings/${f.id}`} className="font-semibold text-ink hover:text-brand-700">
                        {f.title}
                      </Link>
                      <div className="mt-0.5 flex flex-wrap items-center gap-2 text-[11px] text-ink-faint">
                        {f.cve && <code className="rounded bg-red-50 px-1 py-0.5 font-semibold text-red-600">{f.cve}</code>}
                        {f.cwe && <span>{f.cwe}</span>}
                        {f.affected_service && <span>{f.affected_service}</span>}
                        {f.affected_port && <span>:{f.affected_port}</span>}
                      </div>
                    </td>
                    <td className="px-4 py-3"><SeverityBadge severity={f.severity} /></td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <RiskGauge score={f.risk_score} />
                        <span className="text-[10px] font-medium text-ink-faint">{band.label}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3"><PriorityPill priority={aiMap?.[f.id]?.priority} /></td>
                    <td className="px-4 py-3 text-ink-soft">{f.cvss_score ?? "—"}</td>
                    <td className="px-4 py-3"><StatusBadge status={f.status} /></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}