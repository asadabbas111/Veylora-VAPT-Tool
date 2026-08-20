import React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Settings as SettingsIcon, Power, Flame, Database, Cpu, Radar, ShieldAlert, UserCog, RefreshCw } from "lucide-react";
import { api, apiError } from "../lib/api";
import { PageHeader, EmptyState, PageSpinner, StatusBadge } from "../components/badges";
import { Badge, Spinner } from "../components/ui";
import { useAuth } from "../context/AuthContext";
import { fmtDate } from "../lib/utils";

export default function SettingsPage() {
  const { user } = useAuth();
  const qc = useQueryClient();
  const [error, setError] = React.useState("");
  const [seeding, setSeeding] = React.useState(false);

  const { data: killStatus, refetch: refetchKill } = useQuery({
    queryKey: ["kill-switch"],
    queryFn: async () => (await api.get<any>("/admin/kill-switch/status")).data,
  });

  const { data: providers } = useQuery({
    queryKey: ["providers"],
    queryFn: async () => (await api.get<any>("/ai/providers")).data,
  });

  const { data: neo4j } = useQuery({
    queryKey: ["neo4j"],
    queryFn: async () => (await api.get<any>("/attack-paths/neo4j/health")).data,
  });

  const { data: users, refetch: refetchUsers } = useQuery({
    queryKey: ["users"],
    queryFn: async () => (await api.get<any[]>("/admin/users")).data,
    enabled: user?.role === "admin",
  });

  const arm = useMutation({
    mutationFn: async () => {
      try { await api.post("/admin/kill-switch/arm"); } finally { refetchKill(); }
    },
    onError: (e) => setError(apiError(e)),
  });
  const disarm = useMutation({
    mutationFn: async () => {
      try { await api.post("/admin/kill-switch/disarm"); } finally { refetchKill(); }
    },
    onError: (e) => setError(apiError(e)),
  });

  const seedDemo = async () => {
    setSeeding(true);
    setError("");
    try {
      await api.post("/admin/seed-demo");
      qc.invalidateQueries({ queryKey: ["assessments"] });
      qc.invalidateQueries({ queryKey: ["dashboard"] });
    } catch (e) {
      setError(apiError(e));
    } finally {
      setSeeding(false);
    }
  };

  const updateRole = useMutation({
    mutationFn: ({ userId, role }: { userId: number; role: string }) =>
      api.patch(`/admin/users/${userId}`, { role }),
    onSuccess: () => refetchUsers(),
    onError: (e) => setError(apiError(e)),
  });

  if (!user) return <PageSpinner />;

  return (
    <div>
      <PageHeader title="Settings" subtitle="System controls, AI configuration and user management." />

      {error && <div className="mb-4 rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-700">{error}</div>}

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        {/* Kill switch */}
        <div className="card p-5">
          <h3 className="flex items-center gap-2 text-sm font-bold text-ink">
            <Power size={16} className="text-red-500" /> Global Kill Switch
          </h3>
          <p className="mt-1 text-sm text-ink-soft">
            Immediately halts all active scanning, validation and pipeline operations platform-wide. Operations
            resume only after explicit disarm.
          </p>
          <div className="mt-4 flex items-center gap-3">
            <span className={`inline-flex items-center gap-2 rounded-full px-3 py-1 text-sm font-bold ${
              killStatus?.armed ? "bg-red-100 text-red-700" : "bg-emerald-50 text-emerald-700"
            }`}>
              <span className={`h-2 w-2 rounded-full ${killStatus?.armed ? "bg-red-500 animate-pulse" : "bg-emerald-500"}`} />
              {killStatus?.armed ? "ARMED" : "Disarmed"}
            </span>
            {killStatus?.armed ? (
              <button className="btn-secondary" onClick={() => disarm.mutate()} disabled={disarm.isPending}>
                {disarm.isPending ? <Spinner /> : <Power size={15} />} Disarm
              </button>
            ) : (
              <button className="btn-danger" onClick={() => arm.mutate()} disabled={arm.isPending}>
                {arm.isPending ? <Spinner className="h-4 w-4 text-white" /> : <ShieldAlert size={15} />} Arm now
              </button>
            )}
          </div>
        </div>

        {/* Demo seed */}
        <div className="card p-5">
          <h3 className="flex items-center gap-2 text-sm font-bold text-ink">
            <Radar size={16} className="text-brand-600" /> Demonstration Data
          </h3>
          <p className="mt-1 text-sm text-ink-soft">
            Seed the full "Metasploitable Lab Assessment" — an authorized lab network assessment that
            populates the dashboard, findings, risk, attack paths, AI analysis and a report.
          </p>
          <button className="btn-primary mt-4" onClick={seedDemo} disabled={seeding}>
            {seeding ? <Spinner className="h-4 w-4 text-white" /> : <Flame size={15} />} Seed demo assessment
          </button>
        </div>

        {/* AI providers */}
        <div className="card p-5">
          <h3 className="flex items-center gap-2 text-sm font-bold text-ink">
            <Cpu size={16} className="text-brand-600" /> AI Analyst Providers
          </h3>
          <div className="mt-3 space-y-2">
            {(providers?.providers ?? []).map((p: any) => (
              <div key={p.name} className="flex items-center justify-between rounded-lg bg-slate-50 px-3 py-2.5">
                <div>
                  <p className="text-sm font-semibold text-ink">{p.name}</p>
                  <p className="text-xs text-ink-soft">{p.reason}</p>
                </div>
                {providers?.configured === p.name ? (
                  <Badge tone="green">active</Badge>
                ) : p.available ? (
                  <Badge tone="sky">available</Badge>
                ) : (
                  <Badge tone="neutral">optional</Badge>
                )}
              </div>
            ))}
          </div>
          <p className="mt-3 text-xs text-ink-soft">
            Active provider below. OpenAI/Ollama require API configuration via environment variables.
          </p>
        </div>

        {/* Neo4j */}
        <div className="card p-5">
          <h3 className="flex items-center gap-2 text-sm font-bold text-ink">
            <Database size={16} className="text-brand-600" /> Graph Store
          </h3>
          <div className="mt-3 space-y-2">
            <div className="flex items-center justify-between rounded-lg bg-slate-50 px-3 py-2.5">
              <span className="text-sm text-ink">Neo4j adapter</span>
              <StatusBadge status={neo4j?.enabled ? (neo4j?.healthy ? "success" : "failed") : "cancelled"} />
            </div>
            <div className="flex items-center justify-between rounded-lg bg-slate-50 px-3 py-2.5">
              <span className="text-sm text-ink">NetworkX in-memory engine</span>
              <Badge tone="green">ready</Badge>
            </div>
          </div>
          <p className="mt-3 text-xs text-ink-soft">{neo4j?.detail}</p>
        </div>
      </div>

      {/* Users (admin) */}
      {user.role === "admin" && (
        <div className="card mt-6 overflow-hidden">
          <div className="flex items-center gap-2 px-5 py-4">
            <UserCog size={16} className="text-brand-600" />
            <h3 className="text-sm font-bold text-ink">User Management</h3>
          </div>
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-50 text-xs uppercase tracking-wider text-ink-faint">
              <tr>
                <th className="px-5 py-2.5 font-semibold">User</th>
                <th className="px-4 py-2.5 font-semibold">Role</th>
                <th className="px-4 py-2.5 font-semibold">Verified</th>
                <th className="px-4 py-2.5 font-semibold">Joined</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {(users ?? []).map((u) => (
                <tr key={u.id} className="hover:bg-slate-50/60">
                  <td className="px-5 py-3">
                    <p className="font-semibold text-ink">{u.full_name}</p>
                    <p className="text-xs text-ink-soft">{u.email}</p>
                  </td>
                  <td className="px-4 py-3">
                    <select
                      className="input w-32"
                      value={u.role}
                      onChange={(e) => updateRole.mutate({ userId: u.id, role: e.target.value })}
                    >
                      {["admin", "analyst", "viewer"].map((r) => (
                        <option key={r} value={r}>{r}</option>
                      ))}
                    </select>
                  </td>
                  <td className="px-4 py-3">{u.is_verified ? <Badge tone="green">verified</Badge> : <Badge>pending</Badge>}</td>
                  <td className="px-4 py-3 text-xs text-ink-soft">{fmtDate(u.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="card mt-6 flex items-center justify-between p-5 text-sm text-ink-soft">
        <span>Veylora platform · lab-use only · all active operations are scope-enforced</span>
        <RefreshCw size={16} className="text-ink-faint" />
      </div>
    </div>
  );
}