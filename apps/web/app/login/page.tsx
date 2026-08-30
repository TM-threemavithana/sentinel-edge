"use client";

import { ArrowRight, CheckCircle2, Eye, EyeOff, LockKeyhole, Radar, ShieldCheck, Sparkles } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Brand } from "@/components/brand";
import { apiFetch } from "@/lib/api";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("admin@sentinel.local");
  const [password, setPassword] = useState("SentinelDemo!2026");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setError("");
    try {
      await apiFetch("/v1/auth/login", { method: "POST", body: JSON.stringify({ email, password }) });
      router.replace("/dashboard");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Sign-in failed");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="login-page">
      <section className="login-story">
        <div className="login-story-inner">
          <Brand />
          <div className="story-copy">
            <span className="eyebrow"><Sparkles size={14} /> Security at inference speed</span>
            <h1>Your AI traffic.<br /><span>Governed at the edge.</span></h1>
            <p>Inspect every request, enforce adaptive policy, and understand threats before they reach your models or APIs.</p>
            <div className="story-points">
              <span><CheckCircle2 size={17} /> Deterministic + AI threat inspection</span>
              <span><CheckCircle2 size={17} /> Tenant-aware rate limits and controls</span>
              <span><CheckCircle2 size={17} /> Auditable decisions, globally enforced</span>
            </div>
          </div>
          <div className="radar-visual" aria-hidden="true">
            <div className="radar-grid"><i /><i /><i /><span /></div>
            <div className="radar-card primary-radar"><Radar size={20} /><span><small>Requests inspected</small><strong>2.4M</strong></span><em>+18.2%</em></div>
            <div className="radar-card threat-radar"><ShieldCheck size={20} /><span><small>Threats blocked</small><strong>99.98%</strong></span></div>
          </div>
          <p className="login-footnote">Powered by Cloudflare’s global edge network</p>
        </div>
      </section>
      <section className="login-panel">
        <div className="login-form-wrap">
          <span className="mobile-login-brand"><Brand /></span>
          <div className="login-heading"><span className="login-lock"><LockKeyhole size={20} /></span><h2>Welcome back</h2><p>Sign in to your security operations console.</p></div>
          <form onSubmit={submit}>
            <label htmlFor="email">Work email</label>
            <input id="email" name="email" type="email" autoComplete="username" value={email} onChange={(event) => setEmail(event.target.value)} required />
            <div className="password-row"><label htmlFor="password">Password</label><button type="button">Forgot password?</button></div>
            <div className="password-field"><input id="password" name="password" type={showPassword ? "text" : "password"} autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} required /><button type="button" onClick={() => setShowPassword((value) => !value)} aria-label={showPassword ? "Hide password" : "Show password"}>{showPassword ? <EyeOff size={17} /> : <Eye size={17} />}</button></div>
            {error ? <p className="form-error" role="alert">{error}</p> : null}
            <button className="button primary login-submit" type="submit" disabled={submitting}>{submitting ? "Establishing session…" : <>Sign in securely <ArrowRight size={17} /></>}</button>
          </form>
          <div className="sso-separator"><span>or continue with</span></div>
          <button className="button sso-button" type="button" disabled><span className="cf-mark">CF</span> Cloudflare Access <small>configure OIDC</small></button>
          <div className="demo-note"><strong>Portfolio demo credentials are prefilled.</strong><span>Replace local authentication with your OIDC provider before production.</span></div>
          <p className="legal-copy">By signing in, you agree to the acceptable use and privacy policies.</p>
        </div>
      </section>
    </main>
  );
}
