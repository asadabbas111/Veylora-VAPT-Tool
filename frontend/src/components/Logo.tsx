import React from "react";
import { Link } from "react-router-dom";

export function Logo({
  size = 40,
  text = true,
  dark = false,
}: {
  size?: number;
  text?: boolean;
  dark?: boolean;
}) {
  return (
    <div className="flex items-center gap-2.5">
      <img src="/logo.png" alt="logo" width={size} height={size} className="rounded-md shrink-0" style={{ objectFit: "contain" }} />
      {text && (
        <div className="leading-tight">
          <div
            className={`font-extrabold text-[15px] tracking-tight ${dark ? "text-white" : "text-ink"}`}
          >
            Veylora
          </div>
          <div
            className={`text-[11px] font-medium ${dark ? "text-slate-400" : "text-brand-600"}`}
          >
            AI Vulnerability Platform
          </div>
        </div>
      )}
    </div>
  );
}