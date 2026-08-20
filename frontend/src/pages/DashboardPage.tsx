import React from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import {
  Server, Bug, ShieldAlert, Network, GitBranch, Activity, CheckCircle2, Radar,
} from "lucide-react";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, PieChart, Pie, Cell, LineChart, Line, Legend,
} from "recharts";
import { api } from "../lib/api";
import { StatCard } from "../components/ui";
import { PageHeader, StatusBadge, RiskGauge, EmptyState, SeverityBadge, PageSpinner } from "../components/badges";
import type { DashboardData } from "../lib/types";
import { fmtDate, riskBand } from "../lib/utils";

const SEV_COLORS: Record<string, string> = {
  critical: "#dc2626",
  high: "#f97316",
  medium: "#f59e0b",
  low: "#38bdf8",
  info: "#94a3b8",
};

export default function DashboardPage() {
  const { data, isLoading } = useQuery({
    queryKey: ["dashboard"],
    queryFn: async () => (await api.get<DashboardData>("/dashboard/summary")).data,
  });

  if (isLoading || !data) return <PageSpinner label="Loading dashboard…" />;

  const c = data.cards;
  const sevData = data.charts.severity_distribution.filter((s) => s.value > 0);

  return (
    <div>
      <PageHeader
        title="Dashboard"
        subtitle="Real-time security posture across all authorized assessments."
        actions={
          <Link to="/assessments/new" className="btn-primary">
            <Radar size={16} /> New Assessment
          </Link>
        }
      />

      <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
        <StatCard label="Assessments" value={c.assessments} icon={<Radar size={18} />} sub={`${c.active_assessments} active · ${c.completed_assessments} completed`} />
        <StatCard label="Assets Discovered" value={c.total_assets} icon={<Server size={18} />} />
        <StatCard label="Open Vulnerabilities" value={c.open_vulnerabilities} icon={<Bug size={18} />} tone="red" sub={`${c.total_findings - c.open_vulnerabilities} closed`} />
        <StatCard label="Critical Findings" value={c.critical_findings} icon={<ShieldAlert size={18} />} tone="red" sub={`${c.high_findings} high`} />
        <StatCard label="Attack Paths" value={c.attack_paths} icon={<Network size={18} />} tone="violet" />
        <StatCard label="Validated Findings" value={c.validated_findings} icon={<CheckCircle2 size={18} />} tone="green" sub={`${c.remediation_progress}% remediated`} />
      </div>

      <div className="mt-6 grid grid-cols-1 gap-6 xl:grid-cols-3">
        {/* Severity distribution */}
        <div className="card p-5">
          <h3 className="mb-4 flex items-center gap-2 text-sm font-bold text-ink">
            <Activity size={16} className="text-brand-600" /> Vulnerability Severity
          </h3>
          {sevData.length === 0 ? (
            <EmptyState title="No findings yet" subtitle="Run an assessment workflow to populate data." />
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={sevData} dataKey="value" nameKey="key" innerRadius={50} outerRadius={82} paddingAngle={2}>
                  {sevData.map((s) => (
                    <Cell key={s.key} fill={SEV_COLORS[s.key]} />
                  ))}
                </Pie>
                <Legend iconType="circle" />
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          )}
          <div className="mt-2 grid grid-cols-3 gap-2">
            {(["critical", "high", "medium"] as const).map((k) => (
              <div key={k} className="rounded-lg bg-slate-50 p-2 text-center">
                <div className="text-lg font-extrabold" style={{ color: SEV_COLORS[k] }}>
                  {sevData.find((s) => s.key === k)?.value ?? 0}
                </div>
                <div className="text-[11px] font-medium capitalize text-ink-soft">{k}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Risk by asset */}
        <div className="card p-5 xl:col-span-2">
          <h3 className="mb-4 flex items-center gap-2 text-sm font-bold text-ink">
            <Server size={16} className="text-brand-600" /> Risk by Asset
          </h3>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={data.charts.risk_by_asset} layout="vertical" margin={{ left: 10, right: 10 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" horizontal={false} />
              <XAxis type="number" domain={[0, 100]} tick={{ fontSize: 11, fill: "#64748b" }} />
              <YAxis type="category" dataKey="label" width={130} tick={{ fontSize: 11, fill: "#334155" }} />
              <Tooltip formatter={(v: number) => [`${v.toFixed?.(1) ?? v}`, "Risk score"]} />
              <Bar dataKey="value" radius={[0, 6, 6, 0]}>
                {data.charts.risk_by_asset.map((r, i) => (
                  <Cell key={i} fill={r.value >= 80 ? "#dc2626" : r.value >= 60 ? "#f97316" : r.value >= 40 ? "#f59e0b" : "#38bdf8"} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="mt-6 grid grid-cols-1 gap-6 xl:grid-cols-3">
        {/* Trend */}
        <div className="card p-5 xl:col-span-2">
          <h3 className="mb-4 flex items-center gap-2 text-sm font-bold text-ink">
            <GitBranch size={16} className="text-brand-600" /> Findings Over Time
          </h3>
          {data.charts.vulnerability_trend.length < 2 ? (
            <EmptyState title="Not enough data" subtitle="Findings are bucketed by day." />
          ) : (
            <ResponsiveContainer width="100%" height={240}>
              <LineChart data={data.charts.vulnerability_trend} margin={{ left: -20, right: 10 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                <XAxis dataKey="date" tick={{ fontSize: 10, fill: "#64748b" }} />
                <YAxis tick={{ fontSize: 11, fill: "#64748b" }} allowDecimals={false} />
                <Tooltip />
                <Line type="monotone" dataKey="findings" stroke="#0284c7" strokeWidth={2.5} dot={{ r: 3, fill: "#0284c7" }} />
              </LineChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Remediation status */}
        <div className="card p-5">
          <h3 className="mb-4 flex items-center gap-2 text-sm font-bold text-ink">
            <CheckCircle2 size={16} className="text-brand-600" /> Remediation Status
          </h3>
          {data.charts.remediation_status.every((s) => s.value === 0) ? (
            <EmptyState title="No remediation tasks" />
          ) : (
            <ResponsiveContainer width="100%" height={240}>
              <PieChart>
                <Pie data={data.charts.remediation_status.filter((s) => s.value > 0)} dataKey="value" nameKey="key" innerRadius={48} outerRadius={78} paddingAngle={2}>
                  {(data.charts.remediation_status.filter((s) => s.value > 0)).map((s, i) => (
                    <Cell key={i} fill={["#0284c7", "#f97316", "#f59e0b", "#10b981", "#f43f5e", "#34d399", "#94a3b8", "#8b5cf6"][i % 8]} />
                  ))}
                </Pie>
                <Legend iconType="circle" />
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Recent assessments */}
      <div className="card mt-6 overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4">
          <h3 className="text-sm font-bold text-ink">Recent Assessments</h3>
          <Link to="/assessments" className="text-sm font-medium text-brand-700 hover:underline">
            View all →
          </Link>
        </div>
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-50 text-xs uppercase tracking-wider text-ink-faint">
            <tr>
              <th className="px-5 py-2.5 font-semibold">Name</th>
              <th className="px-5 py-2.5 font-semibold">Stage</th>
              <th className="px-5 py-2.5 font-semibold">Status</th>
              <th className="px-5 py-2.5 font-semibold">Progress</th>
              <th className="px-5 py-2.5 font-semibold">Created</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {data.recent_assessments.map((a) => (
              <tr key={a.id} className="hover:bg-slate-50/60">
                <td className="px-5 py-3">
                  <Link to={`/assessments/${a.id}`} className="font-semibold text-ink hover:text-brand-700">
                    {a.name}
                  </Link>
                </td>
                <td className="px-5 py-3 text-ink-soft capitalize">{a.stage.replace(/_/g, " ")}</td>
                <td className="px-5 py-3"><StatusBadge status={a.status} /></td>
                <td className="px-5 py-3">
                  <div className="flex items-center gap-2">
                    <div className="h-1.5 w-24 overflow-hidden rounded-full bg-slate-200">
                      <div className="h-full rounded-full bg-brand-500" style={{ width: `${a.progress}%` }} />
                    </div>
                    <span className="text-xs text-ink-faint">{a.progress}%</span>
                  </div>
                </td>
                <td className="px-5 py-3 text-ink-soft">{fmtDate(a.created_at)}</td>
              </tr>
            ))}
            {data.recent_assessments.length === 0 && (
              <tr>
                <td colSpan={5} className="px-5 py-10 text-center text-ink-faint">
                  No assessments yet.{" "}
                  <Link to="/assessments/new" className="text-brand-700 underline">
                    Create your first one
                  </Link>
                  .
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}