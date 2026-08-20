import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import AuthShell from "../../components/AuthShell";
import { api, apiError } from "../../lib/api";
import { Spinner } from "../../components/ui";
import { Mail, KeyRound, AlertCircle, CheckCircle2 } from "lucide-react";

export default function ForgotPasswordPage() {
  const navigate = useNavigate();
  const [step, setStep] = useState<1 | 2>(1);
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [devCode, setDevCode] = useState("");
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");
  const [loading, setLoading] = useState(false);

  const requestCode = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const { data } = await api.post("/auth/forgot-password", { email });
      setDevCode(String(data.reset_code ?? ""));
      setInfo(String(data.message));
      setStep(2);
    } catch (err: any) {
      setError(apiError(err));
    } finally {
      setLoading(false);
    }
  };

  const resetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await api.post("/auth/reset-password", {
        email,
        code: code.trim(),
        new_password: newPassword,
      });
      setInfo("Password reset. You can now sign in.");
      setStep(3 as 1 | 2);
      setTimeout(() => navigate("/login"), 1800);
    } catch (err: any) {
      setError(apiError(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthShell>
      <h1 className="text-2xl font-extrabold text-ink">Reset password</h1>
      <p className="mt-1 text-sm text-ink-soft">
        Enter your email and we'll send a reset code.
      </p>

      {devCode && (
        <div className="mt-5 flex items-start gap-2 rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm text-amber-800">
          <KeyRound size={18} className="mt-0.5 shrink-0" />
          <div>
            <p className="font-semibold">Emails are off in this lab build — use this code:</p>
            <code className="mt-1 block text-base font-bold tracking-widest text-amber-900">{devCode}</code>
          </div>
        </div>
      )}
      {info && (
        <div className="mt-5 flex items-start gap-2 rounded-lg border border-brand-200 bg-brand-50 p-3 text-sm text-brand-800">
          <CheckCircle2 size={18} className="mt-0.5 shrink-0" />
          {info}
        </div>
      )}
      {error && (
        <div className="mt-5 flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-700">
          <AlertCircle size={18} className="mt-0.5 shrink-0" />
          {error}
        </div>
      )}

      {step === 1 && (
        <form className="mt-6 space-y-4" onSubmit={requestCode}>
          <div>
            <label className="label">Email</label>
            <div className="relative">
              <Mail size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-ink-faint" />
              <input
                className="input pl-9"
                type="email"
                required
                placeholder="you@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>
          </div>
          <button className="btn-primary w-full py-2.5" disabled={loading}>
            {loading && <Spinner className="h-4 w-4 text-white" />}
            Send reset code
          </button>
        </form>
      )}

      {step === 2 && (
        <form className="mt-6 space-y-4" onSubmit={resetPassword}>
          <div>
            <label className="label">Reset code</label>
            <div className="relative">
              <KeyRound size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-ink-faint" />
              <input
                className="input pl-9 tracking-widest"
                inputMode="numeric"
                required
                placeholder="••••••"
                value={code}
                onChange={(e) => setCode(e.target.value)}
              />
            </div>
          </div>
          <div>
            <label className="label">New password</label>
            <input
              className="input"
              type="password"
              required
              minLength={8}
              placeholder="At least 8 chars, 1 uppercase, 1 digit"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
            />
          </div>
          <button className="btn-primary w-full py-2.5" disabled={loading}>
            {loading && <Spinner className="h-4 w-4 text-white" />}
            Set new password
          </button>
        </form>
      )}

      <p className="mt-6 text-center text-sm text-ink-soft">
        Back to{" "}
        <Link to="/login" className="font-semibold text-brand-700 hover:underline">
          Sign in
        </Link>
      </p>
    </AuthShell>
  );
}