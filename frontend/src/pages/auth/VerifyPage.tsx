import React, { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import AuthShell from "../../components/AuthShell";
import { useAuth } from "../../context/AuthContext";
import { api, apiError, saveTokens } from "../../lib/api";
import { Spinner } from "../../components/ui";
import { ShieldCheck, AlertCircle, RefreshCw, MailCheck } from "lucide-react";
import type { Tokens, User } from "../../lib/types";

const CODE_LENGTH = 6;

export default function VerifyPage() {
  const { completeVerification } = useAuth();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const email = params.get("email") || "";
  const dev = params.get("dev");

  const [digits, setDigits] = useState<string[]>(Array(CODE_LENGTH).fill(""));
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [resending, setResending] = useState(false);
  const [sentOtp, setSentOtp] = useState(dev || null);
  const inputsRef = useRef<(HTMLInputElement | null)[]>([]);

  useEffect(() => {
    if (dev) setSentOtp(dev);
  }, [dev]);

  useEffect(() => {
    inputsRef.current[0]?.focus();
  }, []);

  const handleChange = (i: number, v: string) => {
    const c = v.replace(/\D/g, "").slice(-1);
    const next = [...digits];
    next[i] = c;
    setDigits(next);
    if (c && i < CODE_LENGTH - 1) inputsRef.current[i + 1]?.focus();
    setError("");
  };

  const handleKey = (i: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Backspace" && !digits[i] && i > 0) inputsRef.current[i - 1]?.focus();
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    const code = digits.join("");
    if (code.length !== CODE_LENGTH) {
      setError("Enter the 6-digit code.");
      return;
    }
    setLoading(true);
    try {
      const { data } = await api.post<Tokens>("/auth/verify-email", { email, code });
      saveTokens(data, {} as User);
      const me = await api.get<{ user: User }>("/auth/me");
      completeVerification(data, me.data.user);
      navigate("/", { replace: true });
    } catch (err) {
      setError(apiError(err));
      setDigits(Array(CODE_LENGTH).fill(""));
      inputsRef.current[0]?.focus();
    } finally {
      setLoading(false);
    }
  };

  const resend = async () => {
    setResending(true);
    setError("");
    try {
      const { data } = await api.post<{ dev_otp?: string | null }>("/auth/resend-otp", { email });
      if (data.dev_otp) setSentOtp(data.dev_otp);
    } catch (err) {
      setError(apiError(err));
    } finally {
      setResending(false);
    }
  };

  if (!email) {
    return (
      <AuthShell>
        <div className="flex flex-col items-center text-center">
          <AlertCircle size={28} className="text-red-400" />
          <p className="mt-3 font-semibold text-ink">No email provided.</p>
          <Link to="/signup" className="btn-primary mt-4">
            Register
          </Link>
        </div>
      </AuthShell>
    );
  }

  return (
    <AuthShell>
      <div className="flex items-center gap-2">
        <MailCheck className="text-brand-600" size={24} />
        <h1 className="text-2xl font-extrabold text-ink">Verify your email</h1>
      </div>
      <p className="mt-2 text-sm text-ink-soft">
        We sent a 6-digit code to{" "}
        <span className="font-semibold text-ink">{email || "your mailbox"}</span>. Enter it below to
        activate your account and sign in.
      </p>

      {sentOtp && (
        <div className="mt-5 flex items-start gap-2 rounded-lg border border-brand-200 bg-brand-50 p-3 text-sm text-brand-800">
          <ShieldCheck size={18} className="mt-0.5 shrink-0" />
          <div>
            Dev mode — your code is{" "}
            <span className="font-bold tracking-widest">{sentOtp}</span>
          </div>
        </div>
      )}

      {error && (
        <div className="mt-5 flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-700">
          <AlertCircle size={18} className="mt-0.5 shrink-0" />
          {error}
        </div>
      )}

      <form className="mt-7" onSubmit={submit}>
        <div className="flex justify-between gap-2">
          {digits.map((d, i) => (
            <input
              key={i}
              ref={(el) => (inputsRef.current[i] = el)}
              className="input h-14 w-12 px-0 text-center text-xl font-bold text-ink focus:border-brand-500"
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={1}
              value={d}
              onChange={(e) => handleChange(i, e.target.value)}
              onKeyDown={(e) => handleKey(i, e)}
            />
          ))}
        </div>
        <button className="btn-primary mt-6 w-full py-2.5" disabled={loading}>
          {loading && <Spinner className="h-4 w-4 text-white" />}
          Verify & continue
        </button>
      </form>

      <button
        type="button"
        onClick={resend}
        disabled={resending}
        className="mt-5 flex w-full items-center justify-center gap-2 text-sm font-medium text-brand-700 hover:underline disabled:opacity-50"
      >
        <RefreshCw size={14} className={resending ? "animate-spin" : ""} />
        Resend verification code
      </button>

      <p className="mt-6 text-center text-sm text-ink-soft">
        Wrong email?{" "}
        <Link to="/signup" className="font-semibold text-brand-700 hover:underline">
          Register again
        </Link>
      </p>
    </AuthShell>
  );
}