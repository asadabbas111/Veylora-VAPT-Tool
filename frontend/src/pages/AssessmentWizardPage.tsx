import React, { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { api, apiError } from "../lib/api";
import { Spinner } from "../components/ui";
import { PageHeader, SeverityBadge } from "../components/badges";
import { ArrowLeft, ArrowRight, Check, Plus, Trash2, ShieldCheck, AlertTriangle, Lock } from "lucide-react";
import type { Assessment, Scope, Target, Job } from "../lib/types";

const STEPS = ["Details", "Authorized Scope", "Targets", "Run"];

type NewAssessment = {
  name: string;
  client_name: string;
  assessment_type: string;
  start_date: string;
  end_date: string;
  description: string;
  rules_of_engagement: string;
  validation_level: number;
};

export default function AssessmentWizardPage() {
  const navigate = useNavigate();
  const [step, setStep] = useState(0);
  const [assessment, setAssessment] = useState<NewAssessment>({
    name: "",
    client_name: "",
    assessment_type: "vulnerability_assessment",
    start_date: new Date().toISOString().slice(0, 10),
    end_date: "",
    description: "",
    rules_of_engagement: "",
    validation_level: 1,
  });
  const [assessmentId, setAssessmentId] = useState<number | null>(null);
  const [scopes, setScopes] = useState<Scope[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [scopeInput, setScopeInput] = useState("");
  const [targetInput, setTargetInput] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [running, setRunning] = useState(false);
  const [jobId, setJobId] = useState<number | null>(null);
  const [jobStatus, setJobStatus] = useState("");
  const [jobLog, setJobLog] = useState("");

  const update = (k: keyof NewAssessment, v: string | number) =>
    setAssessment((a) => ({ ...a, [k]: v }));

  const createAssessment = async () => {
    setError("");
    setBusy(true);
    try {
      const { data } = await api.post<Assessment>("/assessments", {
        name: assessment.name,
        client_name: assessment.client_name || null,
        assessment_type: assessment.assessment_type,
        start_date: assessment.start_date,
        end_date: assessment.end_date || null,
        description: assessment.description || null,
        rules_of_engagement: assessment.rules_of_engagement || null,
        validation_level: assessment.validation_level,
      });
      setAssessmentId(data.id);
      setStep(1);
    } catch (err) {
      setError(apiError(err));
    } finally {
      setBusy(false);
    }
  };

  const addScope = async () => {
    if (!scopeInput.trim() || !assessmentId) return;
    setError("");
    setNotice(null);
    setBusy(true);
    try {
      const { data } = await api.post<Scope>(
        `/assessments/${assessmentId}/scopes`,
        { target: scopeInput.trim(), description: "Authorized scope" }
      );
      setScopes((s) => [...s, data]);
      setScopeInput("");
    } catch (err) {
      setError(apiError(err));
    } finally {
      setBusy(false);
    }
  };

  const checkTarget = async () => {
    if (!targetInput.trim() || !assessmentId) {
      setError("Enter a target first.");
      return;
    }
    setError("");
    setNotice(null);
    setBusy(true);
    try {
      const { data } = await api.post(`/assessments/${assessmentId}/scope-check`, {
        target: targetInput.trim(),
      });
      setNotice(
        data.in_scope
          ? `In scope ✓ matched ${data.matched_scope}. Adding target…`
          : `BLOCKED: ${data.reason}`
      );
      if (data.in_scope) {
        const { data: t } = await api.post<Target>(`/assessments/${assessmentId}/targets`, {
          target: targetInput.trim(),
        });
        setTargets((x) => [...x, t]);
        setTargetInput("");
        setNotice(null);
      }
    } catch (err) {
      const msg = apiError(err);
      setError(msg.startsWith("BLOCKED") ? msg : msg);
      setNotice(null);
    } finally {
      setBusy(false);
    }
  };

  const startFullWorkflow = async () => {
    if (!assessmentId) return;
    setRunning(true);
    setError("");
    try {
      const { data } = await api.post(`/assessments/${assessmentId}/workflow`, {
        stage: "full",
        adapters: [],
      });
      setJobId(data.job_id);
      setJobStatus("pending");
      pollJob(data.job_id);
    } catch (err) {
      setError(apiError(err));
      setRunning(false);
    }
  };

  const stages = [
    "asset_discovery",
    "vulnerability_scan",
    "risk_calculation",
    "attack_path_analysis",
    "ai_analysis",
    "report_generation",
  ];

  const pollJob = (jid: number) => {
    const tick = async () => {
      if (!assessmentId) return;
      try {
        const { data } = await api.get<Job[]>(`/assessments/${assessmentId}/jobs`);
        const job = data.find((j) => j.id === jid);
        if (!job) {
          setTimeout(tick, 1500);
          return;
        }
        setJobLog(job.log.split("\n").filter(Boolean).slice(-6).join("\n"));
        if (job.status === "completed" || job.status === "failed" || job.status === "cancelled") {
          setJobStatus(job.status);
          setRunning(false);
          if (job.status === "failed") setError(job.error || "Workflow failed.");
        } else {
          setJobStatus(job.status);
          setTimeout(tick, 1500);
        }
      } catch {
        setJobStatus("unknown");
        setRunning(false);
      }
    };
    setTimeout(tick, 1200);
  };

  const goNext = () => {
    setError("");
    setNotice(null);
    if (step === 1 && scopes.length === 0) {
      setError("Add at least one authorized scope entry (e.g. 192.168.56.0/24).");
      return;
    }
    if (step === 2 && targets.filter((t) => t.in_scope).length === 0) {
      setError("Add at least one in-scope target before running.");
      return;
    }
    setStep((s) => Math.min(s + 1, STEPS.length - 1));
  };

  return (
    <div className="mx-auto max-w-3xl">
      <PageHeader
        title="New Assessment"
        subtitle="Define the engagement and its authorized scope. Scope enforcement is server-side and mandatory."
      />

      {/* Stepper */}
      <ol className="mb-8 flex items-center gap-2">
        {STEPS.map((label, i) => (
          <li key={label} className="flex flex-1 items-center gap-2">
            <span
              className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-sm font-bold transition ${
                i < step
                  ? "bg-brand-600 text-white"
                  : i === step
                    ? "bg-white text-brand-700 ring-2 ring-brand-500"
                    : "bg-slate-100 text-ink-faint"
              }`}
            >
              {i < step ? <Check size={15} /> : i + 1}
            </span>
            <span className={`text-sm font-medium ${i === step ? "text-ink" : i < step ? "text-brand-600" : "text-ink-faint"}`}>
              {label}
            </span>
            {i < STEPS.length - 1 && <div className={`h-0.5 flex-1 rounded ${i < step ? "bg-brand-500" : "bg-slate-200"}`} />}
          </li>
        ))}
      </ol>

      {error && (
        <div className="mb-4 flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-700">
          <AlertTriangle size={18} className="mt-0.5 shrink-0" />
          {error}
        </div>
      )}
      {notice && (
        <div className="mb-4 flex items-start gap-2 rounded-lg border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-700">
          <ShieldCheck size={18} className="mt-0.5 shrink-0" />
          {notice}
        </div>
      )}

      {/* STEP 0 — details */}
      {step === 0 && (
        <div className="card grid grid-cols-1 gap-4 p-6 md:grid-cols-2">
          <div>
            <label className="label">Assessment name *</label>
            <input className="input" value={assessment.name} onChange={(e) => update("name", e.target.value)} placeholder="Metasploitable Lab Assessment" />
          </div>
          <div>
            <label className="label">Client / organization</label>
            <input className="input" value={assessment.client_name} onChange={(e) => update("client_name", e.target.value)} placeholder="Cyber Security Research Lab" />
          </div>
          <div>
            <label className="label">Assessment type</label>
            <select className="input" value={assessment.assessment_type} onChange={(e) => update("assessment_type", e.target.value)}>
              <option value="vulnerability_assessment">Vulnerability Assessment</option>
              <option value="penetration_test">Penetration Test</option>
              <option value="red_team">Red Team Exercise</option>
              <option value="security_review">Security Review</option>
            </select>
          </div>
          <div>
            <label className="label">Validation level</label>
            <select className="input" value={assessment.validation_level} onChange={(e) => update("validation_level", +e.target.value)}>
              <option value={0}>0 — Review only (no active testing)</option>
              <option value={1}>1 — Authorized scanning</option>
              <option value={2}>2 — Controlled PoC (requires admin approval)</option>
              <option value={3}>3 — Full authorized exploitation (requires approval)</option>
            </select>
          </div>
          <div>
            <label className="label">Start date</label>
            <input className="input" type="date" value={assessment.start_date} onChange={(e) => update("start_date", e.target.value)} />
          </div>
          <div>
            <label className="label">End date</label>
            <input className="input" type="date" value={assessment.end_date} onChange={(e) => update("end_date", e.target.value)} />
          </div>
          <div className="md:col-span-2">
            <label className="label">Description</label>
            <textarea className="input min-h-20" value={assessment.description} onChange={(e) => update("description", e.target.value)} placeholder="Engagement objectives, environment…" />
          </div>
          <div className="md:col-span-2">
            <label className="label">Rules of engagement</label>
            <textarea className="input min-h-20" value={assessment.rules_of_engagement} onChange={(e) => update("rules_of_engagement", e.target.value)} placeholder="Non-destructive validation only. Active exploitation limited to controlled PoC inside the isolated lab network." />
          </div>
        </div>
      )}

      {/* STEP 1 — scope */}
      {step === 1 && (
        <div>
          <div className="card p-6">
            <div className="flex items-start gap-3 rounded-lg border border-brand-200 bg-brand-50 p-4 text-sm text-brand-800">
              <Lock size={18} className="mt-0.5 shrink-0" />
              <p>
                Every target added later is validated <strong>server-side</strong> against these authorized
                scope entries. Anything outside is blocked before it ever runs.
              </p>
            </div>
            <div className="mt-4 flex gap-2">
              <input
                className="input"
                value={scopeInput}
                onChange={(e) => setScopeInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && addScope()}
                placeholder="e.g. 192.168.56.0/24, 10.0.0.5, lab.example.com"
              />
              <button className="btn-secondary whitespace-nowrap" onClick={addScope} disabled={busy}>
                {busy ? <Spinner /> : <Plus size={16} />} Add scope
              </button>
            </div>
            {scopes.length > 0 && (
              <ul className="mt-4 divide-y divide-slate-100">
                {scopes.map((s) => (
                  <li key={s.id} className="flex items-center justify-between py-2.5">
                    <div>
                      <code className="font-mono text-sm font-semibold text-ink">{s.target}</code>
                      <span className="ml-2 rounded bg-slate-100 px-1.5 py-0.5 text-[11px] font-medium text-ink-soft">{s.target_type}</span>
                    </div>
                    <button onClick={() => setScopes((x) => x.filter((y) => y.id !== s.id))} className="p-1 text-ink-faint hover:text-red-500">
                      <Trash2 size={16} />
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}

      {/* STEP 2 — targets */}
      {step === 2 && (
        <div className="card p-6">
          <div className="flex gap-2">
            <input
              className="input"
              value={targetInput}
              onChange={(e) => setTargetInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && checkTarget()}
              placeholder="Target host or IP (must be in scope)"
            />
            <button className="btn-secondary whitespace-nowrap" onClick={checkTarget} disabled={busy}>
              {busy ? <Spinner /> : <ShieldCheck size={16} />} Check & add
            </button>
          </div>
          <p className="mt-2 text-xs text-ink-soft">
            Each target is checked against the authorized scope. Out-of-scope targets are rejected and logged.
          </p>
          {targets.length > 0 && (
            <ul className="mt-4 divide-y divide-slate-100">
              {targets.map((t) => (
                <li key={t.id} className="flex items-center justify-between py-2.5">
                  <div>
                    <code className="font-mono text-sm font-semibold text-ink">{t.target}</code>
                    <span className="ml-2 rounded bg-emerald-50 px-1.5 py-0.5 text-[11px] font-medium text-emerald-700">in scope</span>
                  </div>
                  <button onClick={() => setTargets((x) => x.filter((y) => y.id !== t.id))} className="p-1 text-ink-faint hover:text-red-500">
                    <Trash2 size={16} />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {/* STEP 3 — run */}
      {step === 3 && (
        <div className="space-y-4">
          <div className="card p-6">
            <h3 className="font-bold text-ink">Automated workflow</h3>
            <ol className="mt-3 space-y-1.5">
              {stages.map((s) => (
                <li key={s} className="flex items-center gap-2 text-sm text-ink-soft">
                  <span className="h-1.5 w-1.5 rounded-full bg-brand-400" />
                  <span className="capitalize">{s.replace(/_/g, " ")}</span>
                </li>
              ))}
            </ol>
            <button className="btn-primary mt-5 w-full py-2.5" onClick={startFullWorkflow} disabled={running || jobStatus === "completed"}>
              {running ? <Spinner className="h-4 w-4 text-white" /> : <RadarIcon />}
              {jobStatus === "completed" ? "Workflow complete" : running ? "Running…" : "Start full workflow"}
            </button>
            {jobStatus && jobStatus !== "" && (
              <div className="mt-4 rounded-lg border border-slate-200 bg-slate-50 p-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold uppercase tracking-wide text-ink-soft">Job #{jobId}</span>
                  <span className="capitalize text-sm font-semibold text-brand-700">{jobStatus}</span>
                </div>
                <pre className="mt-2 max-h-40 overflow-y-auto whitespace-pre-wrap font-mono text-[11px] leading-relaxed text-ink-soft">{jobLog || "Waiting for progress logs…"}</pre>
              </div>
            )}
          </div>
          <div className="card p-5">
            <p className="text-sm text-ink-soft">
              The workflow discovers assets, scans services, computes explainable risk scores, chains attack
              paths, runs AI analysis and generates a formal PDF report. Watch progress on the assessment page.
            </p>
          </div>
        </div>
      )}

      <div className="mt-6 flex items-center justify-between">
        {step > 0 ? (
          <button className="btn-secondary" onClick={() => setStep((s) => Math.max(s - 1, 0))}>
            <ArrowLeft size={16} /> Back
          </button>
        ) : (
          <Link to="/assessments" className="btn-secondary">
            <ArrowLeft size={16} /> Cancel
          </Link>
        )}
        {step === 0 && (
          <button className="btn-primary" onClick={createAssessment} disabled={busy || !assessment.name.trim()}>
            {busy && <Spinner className="h-4 w-4 text-white" />} Create & continue <ArrowRight size={16} />
          </button>
        )}
        {step === 1 && (
          <button className="btn-primary" onClick={goNext}>
            Review targets <ArrowRight size={16} />
          </button>
        )}
        {step === 2 && (
          <button className="btn-primary" onClick={goNext}>
            Run workflow <ArrowRight size={16} />
          </button>
        )}
        {step === 3 && (
          <button className="btn-primary" onClick={() => assessmentId && navigate(`/assessments/${assessmentId}`)}>
            Open assessment page
          </button>
        )}
      </div>
    </div>
  );
}

function RadarIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M19.07 4.93A10 10 0 0 0 6.99 3.34" />
      <path d="M4 6h.01" />
      <path d="M2.29 9.62A10 10 0 1 0 21.31 8.35" />
      <path d="M16.24 7.76A6 6 0 1 0 8.23 16.67" />
      <path d="M12 18h.01" />
      <path d="M17.99 11.66A6 6 0 0 1 15.77 16.67" />
      <circle cx="12" cy="12" r="2" />
      <path d="m13.41 10.59 5.66-5.66" />
    </svg>
  );
}