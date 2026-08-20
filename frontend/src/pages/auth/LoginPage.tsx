import React, { useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import AuthShell from "../../components/AuthShell";
import { useAuth } from "../../context/AuthContext";
import { apiError } from "../../lib/api";
import { Spinner } from "../../components/ui";
import { Mail, Lock, AlertCircle, CheckCircle2 } from "lucide-react";

export default function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setInfo("");
    setLoading(true);
    try {
      const user = await login(email, password);
      navigate(params.get("next") || "/", { replace: true });
    } catch (err: any) {      if (err?.response?.status === 403) {
        setInfo(String(err.response?.data?.detail));
      } else {
        setError(apiError(err));
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthShell>
      <h1 className="text-2xl font-extrabold text-ink">Welcome back</h1>
      <p className="mt-1 text-sm text-ink-soft">
        Sign in to your authorized testing workspace.
      </p>

      {info && (
        <div className="mt-5 flex items-start gap-2 rounded-lg border border-brand-200 bg-brand-50 p-3 text-sm text-brand-800">
          <CheckCircle2 size={18} className="mt-0.5 shrink-0" />
          <div>
            {info}{" "}
            <Link to={`/verify?email=${encodeURIComponent(email)}`} className="font-semibold underline">
              Enter verification code
            </Link>
          </div>
        </div>
      )}
      {error && (
        <div className="mt-5 flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-700">
          <AlertCircle size={18} className="mt-0.5 shrink-0" />
          {error}
        </div>
      )}

      <form className="mt-6 space-y-4" onSubmit={submit}>
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
        <div>
          <div className="flex items-center justify-between">
            <label className="label">Password</label>
            <Link to="/forgot-password" className="text-xs font-semibold text-brand-700 hover:underline">
              Forgot password?
            </Link>
          </div>
          <div className="relative">
            <Lock size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-ink-faint" />
            <input
              className="input pl-9"
              type="password"
              required
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
        </div>
        <button className="btn-primary w-full py-2.5" disabled={loading}>
          {loading && <Spinner className="h-4 w-4 text-white" />}
          Sign in
        </button>
      </form>

      <div className="mt-6 rounded-lg border border-slate-200 bg-white p-3.5 text-xs text-ink-soft">
        <p className="font-semibold text-ink">Demo access</p>
        <p className="mt-1">
          Admin: <code className="rounded bg-slate-100 px-1.5 py-0.5 text-brand-700">admin@secops.io</code> ·{" "}
          <code className="rounded bg-slate-100 px-1.5 py-0.5 text-brand-700">Admin@12345</code>
        </p>
      </div>

      <p className="mt-6 text-center text-sm text-ink-soft">
        New to the platform?{" "}
        <Link to="/signup" className="font-semibold text-brand-700 hover:underline">
          Create an account
        </Link>
      </p>
    </AuthShell>
  );
}