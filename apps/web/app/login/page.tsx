"use client";

import { Activity, ArrowLeft, ArrowRight, CheckCircle2, Copy, Eye, EyeOff, KeyRound, LockKeyhole, ShieldCheck } from "lucide-react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { useEffect, useState } from "react";
import { QRCodeSVG } from "qrcode.react";
import { Brand } from "@/components/brand";
import { apiFetch } from "@/lib/api";

type Phase = "credentials" | "verify" | "enroll" | "recovery";

type LoginResult = {
  mfaRequired?: boolean;
  mfaSetupRequired?: boolean;
  challengeToken?: string;
};

type Enrollment = {
  secret: string;
  uri: string;
  issuer: string;
};

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [accessCheck, setAccessCheck] = useState<"checking" | "local" | "required">("checking");
  const [phase, setPhase] = useState<Phase>("credentials");
  const [challengeToken, setChallengeToken] = useState("");
  const [code, setCode] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [enrollment, setEnrollment] = useState<Enrollment | null>(null);
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let active = true;
    apiFetch<{ enabled: boolean }>("/v1/auth/access", { method: "POST", body: "{}" })
      .then((result) => {
        if (!active) return;
        if (result.enabled) router.replace("/dashboard");
        else setAccessCheck("local");
      })
      .catch((cause) => {
        if (!active) return;
        setAccessCheck("required");
        setError(cause instanceof Error ? cause.message : "Cloudflare Access authentication is required");
      });
    return () => { active = false; };
  }, [router]);

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setError("");
    try {
      const result = await apiFetch<LoginResult>("/v1/auth/login", {
        method: "POST",
        body: JSON.stringify({ email, password }),
      });
      if (result.mfaRequired && result.challengeToken) {
        setChallengeToken(result.challengeToken);
        setPassword("");
        setPhase("verify");
        return;
      }
      if (result.mfaSetupRequired) {
        const setup = await apiFetch<Enrollment>("/v1/auth/mfa/enroll", { method: "POST", body: "{}" });
        setEnrollment(setup);
        setPassword("");
        setPhase("enroll");
        return;
      }
      router.replace("/dashboard");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Sign-in failed");
    } finally {
      setSubmitting(false);
    }
  }

  async function verifyMfa(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setError("");
    try {
      await apiFetch("/v1/auth/mfa/verify", {
        method: "POST",
        body: JSON.stringify({ challengeToken, code }),
      });
      router.replace("/dashboard");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Authenticator verification failed");
    } finally {
      setSubmitting(false);
    }
  }

  async function confirmEnrollment(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (newPassword !== confirmPassword) {
      setError("The new passwords do not match");
      return;
    }
    setSubmitting(true);
    setError("");
    try {
      const result = await apiFetch<{ recoveryCodes: string[] }>("/v1/auth/mfa/confirm", {
        method: "POST",
        body: JSON.stringify({ code, newPassword }),
      });
      setRecoveryCodes(result.recoveryCodes);
      setCode("");
      setNewPassword("");
      setConfirmPassword("");
      setPhase("recovery");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Authenticator enrollment failed");
    } finally {
      setSubmitting(false);
    }
  }

  async function copyRecoveryCodes() {
    await navigator.clipboard.writeText(recoveryCodes.join("\n"));
    setCopied(true);
  }

  function resetCredentials() {
    setPhase("credentials");
    setChallengeToken("");
    setCode("");
    setError("");
  }

  return (
    <main className="login-page">
      <a className="skip-link" href="#login-form">Skip to sign in</a>
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
      <section className="login-panel" id="login-form" tabIndex={-1}>
        <div className="login-form-wrap">
          <span className="mobile-login-brand"><Brand /></span>
          <div className="login-heading"><span className="login-lock">{phase === "credentials" ? <LockKeyhole size={20} /> : <KeyRound size={20} />}</span><h2>{phase === "credentials" ? "Welcome back" : phase === "verify" ? "Verify it’s you" : phase === "enroll" ? "Secure your account" : "Save recovery codes"}</h2><p>{phase === "credentials" ? "Sign in to your security operations console." : phase === "verify" ? "Enter a current authenticator code or a recovery code." : phase === "enroll" ? "Add Sentinel Edge to your authenticator and replace the disclosed password." : "Keep these one-time codes somewhere private and offline."}</p></div>
          {accessCheck === "local" && phase === "credentials" ? <form onSubmit={submit}>
            <label htmlFor="email">Work email</label>
            <input id="email" name="email" type="email" autoComplete="username" spellCheck={false} placeholder="you@example.com" value={email} onChange={(event) => setEmail(event.target.value)} required />
            <div className="password-row"><label htmlFor="password">Password</label></div>
            <div className="password-field"><input id="password" name="password" type={showPassword ? "text" : "password"} autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} required /><button type="button" onClick={() => setShowPassword((value) => !value)} aria-label={showPassword ? "Hide password" : "Show password"}>{showPassword ? <EyeOff size={17} /> : <Eye size={17} />}</button></div>
            {error ? <p className="form-error" role="alert">{error}</p> : null}
            <button className="button primary login-submit" type="submit" disabled={submitting}>{submitting ? "Establishing session…" : <>Sign in securely <ArrowRight size={17} /></>}</button>
          </form> : null}
          {accessCheck === "local" && phase === "verify" ? <form onSubmit={verifyMfa}>
            <button className="login-back" type="button" onClick={resetCredentials}><ArrowLeft size={15} /> Use another account</button>
            <label htmlFor="mfa-code">Authenticator or recovery code</label>
            <input id="mfa-code" name="code" autoComplete="one-time-code" value={code} onChange={(event) => setCode(event.target.value)} placeholder="6-digit or recovery code" required autoFocus />
            {error ? <p className="form-error" role="alert">{error}</p> : null}
            <button className="button primary login-submit" type="submit" disabled={submitting}>{submitting ? "Verifying…" : <>Verify and continue <ArrowRight size={17} /></>}</button>
          </form> : null}
          {accessCheck === "local" && phase === "enroll" && enrollment ? <form onSubmit={confirmEnrollment}>
            <div className="mfa-setup-card">
              <div className="mfa-qr"><QRCodeSVG value={enrollment.uri} size={164} level="M" marginSize={1} /></div>
              <div><strong>1. Scan this QR code</strong><p>Use Google Authenticator, Microsoft Authenticator, 1Password, or any TOTP-compatible app.</p></div>
              <details><summary>Can’t scan it?</summary><code>{enrollment.secret}</code></details>
            </div>
            <label htmlFor="setup-code">2. Enter the 6-digit code</label>
            <input id="setup-code" name="code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} value={code} onChange={(event) => setCode(event.target.value.replace(/\D/gu, ""))} placeholder="123456" required />
            <label htmlFor="new-password">3. Choose a new password</label>
            <input id="new-password" name="new-password" type="password" autoComplete="new-password" minLength={16} value={newPassword} onChange={(event) => setNewPassword(event.target.value)} required />
            <p className="field-help">Use at least 16 characters. Your previous password cannot be reused.</p>
            <label htmlFor="confirm-password">Confirm new password</label>
            <input id="confirm-password" name="confirm-password" type="password" autoComplete="new-password" minLength={16} value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} required />
            {error ? <p className="form-error" role="alert">{error}</p> : null}
            <button className="button primary login-submit" type="submit" disabled={submitting}>{submitting ? "Securing account…" : <>Enable authenticator <ShieldCheck size={17} /></>}</button>
          </form> : null}
          {accessCheck === "local" && phase === "recovery" ? <div className="recovery-panel">
            <div className="recovery-codes" aria-label="One-time recovery codes">{recoveryCodes.map((recoveryCode) => <code key={recoveryCode}>{recoveryCode}</code>)}</div>
            <button className="button secondary recovery-copy" type="button" onClick={copyRecoveryCodes}><Copy size={16} /> {copied ? "Copied" : "Copy codes"}</button>
            <p className="recovery-warning">Each code works once. They will not be shown again.</p>
            <button className="button primary login-submit" type="button" onClick={() => router.replace("/dashboard")}>I saved these codes <ArrowRight size={17} /></button>
          </div> : null}
          {accessCheck !== "local" ? <div className="access-login-state" role="status"><span className="cf-mark">CF</span><strong>{accessCheck === "checking" ? "Checking sign-in configuration…" : "Cloudflare Access required"}</strong>{error ? <p className="form-error" role="alert">{error}</p> : null}</div> : null}
          <div className="demo-note"><strong>Authorized workspace access only.</strong><span>Use the account issued by your Sentinel Edge administrator.</span></div>
          <p className="legal-copy">By signing in, you agree to the acceptable use and privacy policies. <Link href="/showcase">View the public showcase.</Link></p>
        </div>
      </section>
    </main>
  );
}
