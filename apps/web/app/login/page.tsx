"use client";

import { Activity, ArrowRight, CheckCircle2, Eye, EyeOff, LockKeyhole, ShieldCheck } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Brand } from "@/components/brand";
import { apiFetch } from "@/lib/api";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
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
            <span className="eyebrow"><ShieldCheck size={14} /> Security operations, at the edge</span>
            <h1>Control every<br /><span>AI request.</span></h1>
            <p>See what is moving through your gateway, understand why it was allowed or blocked, and act before risk reaches production.</p>
            <div className="story-points">
              <span><CheckCircle2 size={17} /> Explainable policy decisions</span>
              <span><CheckCircle2 size={17} /> Tenant-aware controls and rate limits</span>
              <span><CheckCircle2 size={17} /> Complete administrative audit trail</span>
            </div>
          </div>
          <div className="login-signal-preview" aria-label="Illustrative gateway activity">
            <div className="signal-preview-head"><span><Activity size={15} /> Gateway activity</span><em>Illustrative data</em></div>
            <div className="signal-preview-row"><span className="signal-method">POST</span><code>/v1/chat/completions</code><span className="signal-risk critical">96 risk</span><strong>Blocked</strong></div>
            <div className="signal-preview-row"><span className="signal-method">POST</span><code>/v1/embeddings</code><span className="signal-risk safe">12 risk</span><strong>Allowed</strong></div>
            <div className="signal-preview-row"><span className="signal-method get">GET</span><code>/v1/models</code><span className="signal-risk safe">04 risk</span><strong>Allowed</strong></div>
          </div>
          <p className="login-footnote"><span /> Cloudflare-native control plane</p>
        </div>
      </section>
      <section className="login-panel">
        <div className="login-form-wrap">
          <span className="mobile-login-brand"><Brand /></span>
          <div className="login-heading"><span className="login-lock"><LockKeyhole size={20} /></span><h2>Welcome back</h2><p>Sign in to your security operations console.</p></div>
          <form onSubmit={submit}>
            <label htmlFor="email">Work email</label>
            <input id="email" name="email" type="email" autoComplete="username" value={email} onChange={(event) => setEmail(event.target.value)} required />
            <div className="password-row"><label htmlFor="password">Password</label></div>
            <div className="password-field"><input id="password" name="password" type={showPassword ? "text" : "password"} autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} required /><button type="button" onClick={() => setShowPassword((value) => !value)} aria-label={showPassword ? "Hide password" : "Show password"}>{showPassword ? <EyeOff size={17} /> : <Eye size={17} />}</button></div>
            {error ? <p className="form-error" role="alert">{error}</p> : null}
            <button className="button primary login-submit" type="submit" disabled={submitting}>{submitting ? "Establishing session…" : <>Sign in securely <ArrowRight size={17} /></>}</button>
          </form>
          <div className="sso-separator"><span>or continue with</span></div>
          <button className="button sso-button" type="button" disabled><span className="cf-mark">CF</span> Cloudflare Access <small>configure OIDC</small></button>
          <div className="demo-note"><strong>Authorized workspace access only.</strong><span>Use the account issued by your Sentinel Edge administrator.</span></div>
          <p className="legal-copy">By signing in, you agree to the acceptable use and privacy policies.</p>
        </div>
      </section>
    </main>
  );
}
