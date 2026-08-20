import React from "react";
import { Link, useLocation, useNavigate, Outlet } from "react-router-dom";
import {
  LayoutDashboard,
  Target,
  ShieldCheck,
  Server,
  Bug,
  Network,
  ClipboardList,
  FileText,
  ListChecks,
  Settings,
  LogOut,
  Menu,
  X,
} from "lucide-react";
import { Logo } from "./Logo";
import { useAuth } from "../context/AuthContext";
import { Avatar } from "./badges";
import { timeAgo } from "../lib/utils";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";

const NAV = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/assessments", label: "Assessments", icon: Target },
  { to: "/audit", label: "Audit Log", icon: ListChecks },
  { to: "/settings", label: "Settings", icon: Settings },
];

export function AppLayout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [open, setOpen] = React.useState(false);

  const { data: auditCount } = useQuery({
    queryKey: ["audit-count"],
    queryFn: async () => {
      const { data } = await api.get<{ total: number }>("/audit?page=1&page_size=1");
      return data.total;
    },
    enabled: !!user,
  });

  const assessmentId = location.pathname.split("/")[2];
  const isAssessmentPage = location.pathname.startsWith("/assessments/") && assessmentId && !isNaN(+assessmentId);

  const subNav = isAssessmentPage
    ? [
        { to: `/assessments/${assessmentId}`, label: "Overview", icon: ShieldCheck },
        { to: `/assessments/${assessmentId}/assets`, label: "Assets", icon: Server },
        { to: `/assessments/${assessmentId}/findings`, label: "Findings", icon: Bug },
        { to: `/assessments/${assessmentId}/attack-paths`, label: "Attack Paths", icon: Network },
        { to: `/assessments/${assessmentId}/remediation`, label: "Remediation", icon: ClipboardList },
        { to: `/assessments/${assessmentId}/reports`, label: "Reports", icon: FileText },
      ]
    : [];

  const nav = (
    <nav className="flex flex-1 flex-col gap-1 px-3 py-4">
      {NAV.map((item) => {
        const active = item.end ? location.pathname === item.to : location.pathname.startsWith(item.to);
        return (
          <Link
            key={item.to}
            to={item.to}
            onClick={() => setOpen(false)}
            className={`flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition ${
              active
                ? "bg-brand-50 text-brand-700 ring-1 ring-brand-100"
                : "text-ink-soft hover:bg-slate-50 hover:text-ink"
            }`}
          >
            <item.icon size={18} className={active ? "text-brand-600" : ""} />
            {item.label}
            {item.to === "/audit" && !!auditCount && (
              <span className="ml-auto rounded-full bg-brand-100 px-2 py-0.5 text-[10px] font-bold text-brand-700">
                {auditCount}
              </span>
            )}
          </Link>
        );
      })}
      {subNav.length > 0 && (
        <div className="mt-2 border-t border-slate-200 pt-2">
          <p className="px-3 pb-1 text-[10px] font-bold uppercase tracking-wider text-ink-faint">
            Assessment
          </p>
          {subNav.map((item) => {
            const active = location.pathname.startsWith(item.to);
            return (
              <Link
                key={item.to}
                to={item.to}
                onClick={() => setOpen(false)}
                className={`flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition ${
                  active ? "bg-brand-50 text-brand-700 ring-1 ring-brand-100" : "text-ink-soft hover:bg-slate-50 hover:text-ink"
                }`}
              >
                <item.icon size={18} className={active ? "text-brand-600" : ""} />
                {item.label}
              </Link>
            );
          })}
        </div>
      )}
    </nav>
  );

  const sidebarInner = (
    <div className="flex h-full flex-col">
      <div className="flex h-16 items-center border-b border-slate-200 px-5">
        <Link to="/" onClick={() => setOpen(false)}>
          <Logo />
        </Link>
      </div>
      {nav}
      <div className="border-t border-slate-200 p-3">
        <div className="flex items-center gap-3 rounded-lg bg-slate-50 px-3 py-2.5">
          <Avatar name={user?.full_name} />
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-semibold text-ink">{user?.full_name}</p>
            <p className="truncate text-xs text-ink-soft">
              {user?.role}
              {user?.last_login_at ? ` · ${timeAgo(user.last_login_at)}` : ""}
            </p>
          </div>
          <button
            title="Sign out"
            onClick={() => {
              logout();
              navigate("/login");
            }}
            className="rounded-md p-1.5 text-ink-faint hover:bg-white hover:text-red-500"
          >
            <LogOut size={16} />
          </button>
        </div>
      </div>
    </div>
  );

  return (
    <div className="flex min-h-screen">
      {/* Desktop sidebar */}
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-64 border-r border-slate-200 bg-white lg:block">
        {sidebarInner}
      </aside>

      {/* Mobile sidebar */}
      {open && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div className="absolute inset-0 bg-slate-900/40 backdrop-blur-sm" onClick={() => setOpen(false)} />
          <aside className="absolute inset-y-0 left-0 w-72 bg-white shadow-2xl">
            <button onClick={() => setOpen(false)} className="absolute right-3 top-4 rounded-md p-1 text-ink-faint hover:bg-slate-100">
              <X size={20} />
            </button>
            {sidebarInner}
          </aside>
        </div>
      )}

      <div className="flex min-h-screen flex-1 flex-col lg:pl-64">
        <header className="sticky top-0 z-20 flex h-16 items-center gap-4 border-b border-slate-200 bg-white/80 px-4 backdrop-blur lg:px-8">
          <button className="rounded-md p-1.5 text-ink-soft hover:bg-slate-100 lg:hidden" onClick={() => setOpen(true)}>
            <Menu size={20} />
          </button>
          <div className="flex-1 text-sm text-ink-soft">
            Authorized testing platform · all operations are scope-enforced
          </div>
          <span className="hidden items-center gap-1.5 rounded-full bg-emerald-50 px-3 py-1 text-xs font-medium text-emerald-700 ring-1 ring-emerald-200 sm:inline-flex">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse" />
            System Online
          </span>
        </header>
        <main className="flex-1 px-4 py-6 lg:px-8">
          <Outlet />
        </main>
        <footer className="px-8 py-4 text-center text-xs text-ink-faint">
          Veylora — AI Autonomous Vulnerability Assessment & Authorized Penetration Testing Platform · Lab-use only
        </footer>
      </div>
    </div>
  );
}