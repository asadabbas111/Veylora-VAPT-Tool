import React from "react";
import { Logo } from "./Logo";
import { ShieldCheck, Lock, MailCheck } from "lucide-react";

export default function AuthShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen">
      {/* Brand panel */}
      <div className="relative hidden w-[46%] flex-col justify-between overflow-hidden bg-gradient-to-br from-brand-700 via-brand-600 to-cyan-500 p-10 lg:flex">
        <div className="absolute -right-24 -top-24 h-96 w-96 rounded-full bg-white/10 blur-2xl" />
        <div className="absolute -bottom-32 -left-20 h-80 w-80 rounded-full bg-cyan-300/20 blur-2xl" />
        <div className="relative">
          <div className="rounded-2xl bg-white/10 p-4 backdrop-blur inline-flex">
            <img src="/logo.png" alt="logo" width={48} height={48} className="rounded-lg" />
          </div>
          <h1 className="mt-8 max-w-md text-4xl font-extrabold leading-tight tracking-tight text-white">
            AI Autonomous Vulnerability Assessment Platform
          </h1>
          <p className="mt-4 max-w-md text-brand-100">
            An authorized penetration-testing platform that discovers, validates and explains
            attack paths — with server-side scope enforcement and a full audit trail.
          </p>
        </div>
        <div className="relative grid grid-cols-3 gap-4">
          {[
            { icon: ShieldCheck, text: "Scope-enforced testing" },
            { icon: Lock, text: "RBAC + audit log" },
            { icon: MailCheck, text: "OTP email verification" },
          ].map((f, i) => (
            <div key={i} className="rounded-xl bg-white/10 p-3.5 backdrop-blur">
              <f.icon className="text-white" size={20} />
              <p className="mt-2 text-xs font-semibold text-white">{f.text}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Form panel */}
      <div className="flex flex-1 items-center justify-center bg-[#f5f9fc] px-6 py-12">
        <div className="w-full max-w-md">
          <div className="mb-8 lg:hidden">
            <Logo size={44} />
          </div>
          {children}
        </div>
      </div>
    </div>
  );
}