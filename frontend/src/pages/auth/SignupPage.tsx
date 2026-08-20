import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import AuthShell from "../../components/AuthShell";
import { api, apiError } from "../../lib/api";
import { Spinner } from "../../components/ui";
import { User, Mail, Lock, AlertCircle, MailCheck } from "lucide-react";

export default function SignupPage() {
  const navigate = useNavigate();
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [devOtp, setDevOtp] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const strength =
    password.length >= 8 && /[A-Z]/.test(password) && /\d/.test(password)
      ? "Strong"
      : password.length > 0
        ? "Weak — needs 8+ chars, an uppercase letter and a digit"
        : "";

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    if (password !== confirm) {
      setError("Passwords do not match.");
      return;
    }
    if (strength !== "Strong") {
      setError("Weak password — needs 8+ chars, an uppercase letter and a digit.");
      return;
    }
    setLoading(true);
    try {
      const { data } = await api.post("/auth/register", {
        full_name: fullName,
        email,
        password,
      });
      setDevOtp(data.dev_otp ?? null);
      navigate(`/verify?email=${encodeURIComponent(email)}&dev=${data.dev_otp ?? ""}`);
    } catch (err) {
      setError(apiError(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthShell>
      <div className="flex items-center gap-2">
        <MailCheck className="text-brand-600" size={22} />
        <h1 className="text-2xl font-extrabold text-ink">Create your account</h1>
      </div>
      <p className="mt-1 text-sm text-ink-soft">
        Registration is protected by email OTP verification — a code will be sent to your
        mailbox.
      </p>

      {devOtp && (
        <div className="mt-5 flex items-start gap-2 rounded-lg border border-brand-200 bg-brand-50 p-3 text-sm text-brand-800">
          <MailCheck size={18} className="mt-0.5 shrink-0" />
          <div>
            Development mode — your verification code is{" "}
            <span className="font-bold tracking-widest">{devOtp}</span>. Continue to verify.
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
          <label className="label">Full name</label>
          <div className="relative">
            <User size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-ink-faint" />
            <input className="input pl-9" required minLength={2} placeholder="Jane Analyst" value={fullName} onChange={(e) => setFullName(e.target.value)} />
          </div>
        </div>
        <div>
          <label className="label">Email</label>
          <div className="relative">
            <Mail size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-ink-faint" />
            <input className="input pl-9" type="email" required placeholder="you@gmail.com" value={email} onChange={(e) => setEmail(e.target.value)} />
          </div>
        </div>
        <div>
          <label className="label">Password</label>
          <div className="relative">
            <Lock size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-ink-faint" />
            <input className="input pl-9" type="password" required placeholder="At least one uppercase letter and a digit" value={password} onChange={(e) => setPassword(e.target.value)} />
          </div>
          {strength && <p className="mt-1 text-xs text-ink-soft">{strength}</p>}
        </div>
        <div>
          <label className="label">Confirm password</label>
          <div className="relative">
            <Lock size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-ink-faint" />
            <input className="input pl-9" type="password" required value={confirm} onChange={(e) => setConfirm(e.target.value)} />
          </div>
        </div>
        <button className="btn-primary w-full py-2.5" disabled={loading}>
          {loading && <Spinner className="h-4 w-4 text-white" />}
          Create account
        </button>
      </form>

      <p className="mt-6 text-center text-sm text-ink-soft">
        Already have an account?{" "}
        <Link to="/login" className="font-semibold text-brand-700 hover:underline">
          Sign in
        </Link>
      </p>
    </AuthShell>
  );
}