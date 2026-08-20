import React from "react";
import { useQuery } from "@tanstack/react-query";
import { ListChecks, Search } from "lucide-react";
import { api } from "../lib/api";
import { PageHeader, EmptyState, PageSpinner, StatusBadge } from "../components/badges";
import type { AuditEntry } from "../lib/types";
import { fmtDateTime, timeAgo } from "../lib/utils";

export default function AuditPage() {
  const [page, setPage] = React.useState(1);
  const [search, setSearch] = React.useState("");

  const { data, isLoading } = useQuery({
    queryKey: ["audit", page, search],
    queryFn: async () =>
      (
        await api.get<{ items: AuditEntry[]; total: number }>("/audit", {
          params: { page, page_size: 50, search: search || undefined },
        })
      ).data,
  });

  const filtered = (data?.items ?? []).filter((a) => {
    if (!search) return true;
    const q = search.toLowerCase();
    return (
      (a.action || "").toLowerCase().includes(q) ||
      (a.user || "").toLowerCase().includes(q) ||
      (a.detail || "").toLowerCase().includes(q) ||
      (a.object_type || "").toLowerCase().includes(q)
    );
  });

  const totalPages = Math.max(1, Math.ceil((data?.total ?? 0) / 50));

  return (
    <div>
      <PageHeader
        title="Audit Log"
        subtitle="Append-only, immutable record of every action performed in the platform."
        actions={
          <div className="relative">
            <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-ink-faint" />
            <input className="input w-64 pl-9" placeholder="Filter by action, user, detail…" value={search} onChange={(e) => setSearch(e.target.value)} />
          </div>
        }
      />

      <div className="mb-4 flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-4 py-3 text-xs text-ink-soft">
        <ListChecks size={16} className="text-brand-600" />
        {data?.total ?? 0} audit entries recorded. Entries are cryptographically stored and cannot be edited.
      </div>

      {isLoading ? (
        <PageSpinner />
      ) : (
        <div className="card overflow-hidden">
          {!filtered.length ? (
            <div className="p-6">
              <EmptyState icon={<ListChecks size={36} />} title="No audit entries" />
            </div>
          ) : (
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-50 text-xs uppercase tracking-wider text-ink-faint">
                <tr>
                  <th className="px-5 py-3 font-semibold">Timestamp</th>
                  <th className="px-4 py-3 font-semibold">Actor</th>
                  <th className="px-4 py-3 font-semibold">Action</th>
                  <th className="px-4 py-3 font-semibold">Object</th>
                  <th className="px-4 py-3 font-semibold">Result</th>
                  <th className="px-4 py-3 font-semibold">Detail</th>
                  <th className="px-4 py-3 font-semibold">IP</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {filtered.map((a) => (
                  <tr key={a.id} className="hover:bg-slate-50/60">
                    <td className="whitespace-nowrap px-5 py-3 text-xs text-ink-soft" title={fmtDateTime(a.timestamp)}>
                      {timeAgo(a.timestamp)}
                    </td>
                    <td className="px-4 py-3">
                      <span className="font-medium text-ink">{a.user ?? `#${a.user_id ?? "?"}`}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="font-semibold text-ink">{a.action}</span>
                    </td>
                    <td className="px-4 py-3 text-xs text-ink-soft">
                      {a.object_type ? (
                        <>
                          {a.object_type}
                          {a.object_id ? ` #${a.object_id}` : ""}
                        </>
                      ) : "—"}
                    </td>
                    <td className="px-4 py-3">
                      {a.result ? <StatusBadge status={a.result} /> : <span className="text-ink-faint">—</span>}
                    </td>
                    <td className="max-w-xs truncate px-4 py-3 text-xs text-ink-faint" title={a.detail ?? ""}>
                      {a.detail ?? ""}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-ink-faint">{a.ip_address ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <div className="flex items-center justify-between border-t border-slate-100 px-5 py-3">
            <span className="text-xs text-ink-soft">Page {page} of {totalPages}</span>
            <div className="flex gap-2">
              <button className="btn-secondary text-xs" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
                Previous
              </button>
              <button className="btn-secondary text-xs" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>
                Next
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}