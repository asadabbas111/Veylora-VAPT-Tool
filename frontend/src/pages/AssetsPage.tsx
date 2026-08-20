import React from "react";
import { useQuery } from "@tanstack/react-query";
import { useParams, Link } from "react-router-dom";
import { Server, Search } from "lucide-react";
import { api } from "../lib/api";
import { PageHeader, SeverityBadge, EmptyState, PageSpinner } from "../components/badges";
import { RiskGauge } from "../components/badges";
import type { Asset, Finding } from "../lib/types";

export default function AssetsPage() {
  const { id } = useParams();
  const aid = Number(id);
  const [search, setSearch] = React.useState("");

  const { data: assets, isLoading } = useQuery({
    queryKey: ["assets", aid, search],
    queryFn: async () =>
      (await api.get<Asset[]>(`/assets`, { params: { assessment_id: aid, search: search || undefined } })).data,
  });

  const { data: findings } = useQuery({
    queryKey: ["assets-findings", aid],
    queryFn: async () =>
      (await api.get<{ items: Finding[] }>("/findings", { params: { assessment_id: aid, page_size: 200 } })).data.items,
  });

  const severityOf = (assetId: number) => {
    const list = (findings ?? []).filter((f) => f.asset_id === assetId);
    const count = (sev: string) => list.filter((f) => f.severity === sev).length;
    return { critical: count("critical"), high: count("high"), medium: count("medium"), low: count("low"), info: count("info") };
  };

  const filtered = (assets ?? []).filter((a) => {
    if (!search) return true;
    const q = search.toLowerCase();
    return (a.ip_address || "").includes(q) || (a.hostname || "").includes(q) || (a.os_name || "").includes(q);
  });

  return (
    <div>
      <PageHeader
        title="Assets"
        subtitle="Discovered hosts within the authorized scope."
        actions={
          <div className="relative">
            <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-ink-faint" />
            <input className="input w-64 pl-9" placeholder="Search host, IP, OS…" value={search} onChange={(e) => setSearch(e.target.value)} />
          </div>
        }
      />

      {isLoading ? (
        <PageSpinner />
      ) : !filtered.length ? (
        <EmptyState icon={<Server size={40} />} title="No assets discovered" subtitle="Run the asset discovery workflow stage." />
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {filtered.map((a) => {
            const sev = severityOf(a.id);
            return (
              <div key={a.id} className="card p-5">
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3">
                    <div className="flex h-11 w-11 items-center justify-center rounded-lg bg-brand-50 text-brand-600 ring-1 ring-brand-100">
                      <Server size={20} />
                    </div>
                    <div>
                      <code className="text-sm font-bold text-ink">{a.ip_address}</code>
                      {a.hostname && <p className="text-xs text-ink-soft">{a.hostname}</p>}
                    </div>
                  </div>
                  <RiskGauge score={a.risk_score} />
                </div>
                <div className="mt-4 flex flex-wrap items-center gap-1.5">
                  {Object.entries(sev).map(([k, v]) =>
                    v > 0 ? <SeverityBadge key={k} severity={k} /> : null
                  )}
                  {Object.values(sev).every((v) => v === 0) && (
                    <span className="text-xs text-ink-faint">No findings</span>
                  )}
                </div>
                <div className="mt-3 flex items-center justify-between text-xs text-ink-faint">
                  <span>{a.os_name || "Unknown OS"}</span>
                  <span className="rounded bg-slate-100 px-1.5 py-0.5 font-medium text-ink-soft">
                    criticality {a.criticality}/10
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}