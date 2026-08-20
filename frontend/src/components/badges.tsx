import React from "react";
import { Link } from "react-router-dom";
import { X } from "lucide-react";
import { severityText, statusText, initials } from "../lib/utils";
import { Spinner } from "./ui";

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span
      className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-semibold capitalize ${severityText(severity)}`}
    >
      {severity}
    </span>
  );
}

export function StatusBadge({ status }: { status: string }) {
  return (
    <span
      className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium capitalize ${statusText(status)}`}
    >
      {status}
    </span>
  );
}

export function PriorityPill({ priority }: { priority?: string | null }) {
  const map: Record<string, string> = {
    P1: "bg-red-600 text-white",
    P2: "bg-orange-500 text-white",
    P3: "bg-amber-400 text-white",
    P4: "bg-slate-400 text-white",
  };
  return (
    <span
      className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-bold ${map[priority ?? ""] ?? "bg-slate-200 text-slate-700"}`}
    >
      {priority ?? "—"}
    </span>
  );
}

export function Avatar({ name }: { name?: string }) {
  return (
    <span className="inline-flex h-8 w-8 items-center justify-center rounded-full bg-brand-100 text-xs font-bold text-brand-700 ring-1 ring-brand-200">
      {initials(name)}
    </span>
  );
}

export function RiskGauge({ score }: { score: number }) {
  const color =
    score >= 80 ? "text-red-600" : score >= 60 ? "text-orange-500" : score >= 40 ? "text-amber-500" : "text-sky-500";
  return <span className={`text-lg font-bold ${color}`}>{score.toFixed(1)}</span>;
}

export function Modal({
  open,
  onClose,
  title,
  children,
  wide = false,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
  wide?: boolean;
}) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 backdrop-blur-sm p-4" onClick={onClose}>
      <div
        className={`card w-full ${wide ? "max-w-3xl" : "max-w-md"} max-h-[90vh] overflow-y-auto`}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-slate-200 px-5 py-3.5">
          <h3 className="text-base font-bold text-ink">{title}</h3>
          <button onClick={onClose} className="rounded-md p-1 text-ink-faint hover:bg-slate-100 hover:text-ink">
            <X size={18} />
          </button>
        </div>
        <div className="p-5">{children}</div>
      </div>
    </div>
  );
}

export function PageSpinner({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-24 text-ink-soft">
      <Spinner className="h-8 w-8 text-brand-600" />
      <p className="mt-3 text-sm">{label}</p>
    </div>
  );
}

export function EmptyState({
  icon,
  title,
  subtitle,
  action,
}: {
  icon?: React.ReactNode;
  title: string;
  subtitle?: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-slate-300 bg-white px-6 py-16 text-center">
      {icon && <div className="mb-3 text-ink-faint">{icon}</div>}
      <h3 className="text-base font-semibold text-ink">{title}</h3>
      {subtitle && <p className="mt-1 max-w-md text-sm text-ink-soft">{subtitle}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: string;
  subtitle?: React.ReactNode;
  actions?: React.ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
      <div>
        <h1 className="text-2xl font-extrabold tracking-tight text-ink">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-ink-soft">{subtitle}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}

export function DiscoveredLink({
  to,
  children,
}: {
  to: string;
  children: React.ReactNode;
}) {
  return (
    <Link to={to} className="text-brand-700 underline-offset-2 hover:underline">
      {children}
    </Link>
  );
}