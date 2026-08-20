import React from "react";
import { Loader2 } from "lucide-react";

export function Spinner({ className = "h-4 w-4 text-brand-600" }: { className?: string }) {
  return <Loader2 className={`animate-spin ${className}`} />;
}

export function Badge({ children, tone = "neutral" }: { children: React.ReactNode; tone?: string }) {
  const tones: Record<string, string> = {
    neutral: "bg-slate-100 text-slate-600 border-slate-200",
    sky: "bg-brand-100 text-brand-700 border-brand-200",
    green: "bg-emerald-50 text-emerald-700 border-emerald-200",
    red: "bg-red-50 text-red-600 border-red-200",
    amber: "bg-amber-50 text-amber-700 border-amber-200",
  };
  return (
    <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-semibold ${tones[tone] ?? tones.neutral}`}>
      {children}
    </span>
  );
}

export function StatCard({
  label,
  value,
  icon,
  tone = "sky",
  sub,
}: {
  label: string;
  value: React.ReactNode;
  icon?: React.ReactNode;
  tone?: "sky" | "red" | "amber" | "green" | "slate" | "violet";
  sub?: string;
}) {
  const tones: Record<string, string> = {
    sky: "bg-brand-50 text-brand-600 ring-brand-100",
    red: "bg-red-50 text-red-500 ring-red-100",
    amber: "bg-amber-50 text-amber-500 ring-amber-100",
    green: "bg-emerald-50 text-emerald-500 ring-emerald-100",
    slate: "bg-slate-100 text-slate-500 ring-slate-200",
    violet: "bg-violet-50 text-violet-500 ring-violet-100",
  };
  return (
    <div className="card px-5 py-4">
      <div className="flex items-center justify-between">
        <p className="text-sm font-medium text-ink-soft">{label}</p>
        {icon && (
          <span className={`inline-flex h-9 w-9 items-center justify-center rounded-lg ring-1 ${tones[tone]}`}>
            {icon}
          </span>
        )}
      </div>
      <p className="mt-2 text-2xl font-extrabold text-ink">{value}</p>
      {sub && <p className="mt-0.5 text-xs text-ink-faint">{sub}</p>}
    </div>
  );
}