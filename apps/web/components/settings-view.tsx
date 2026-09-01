"use client";

import { Bot, Box, Check, CirclePlus, Cloud, Copy, Database, Globe2, RadioTower, ServerCog, Waypoints } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { ApiError, apiFetch } from "@/lib/api";
import { PageHeader, StatusBadge } from "./page-header";

interface Upstream {
  id: string;
  name: string;
  base_url: string;
  timeout_ms: number;
  status: string;
  created_at: string;
}

interface RuntimeStatus {
  environment: string;
  freeTierMode: boolean;
  aiEnabled: boolean;
  artifactStorageEnabled: boolean;
  queueEnabled: boolean;
  policyCacheEnabled: boolean;
  coordinatorEnabled: boolean;
}

const bindings = [
  { label: "Structured data", value: "D1", note: "Policies, identities, events", icon: Database, tone: "blue" },
  { label: "Artifacts", value: "R2", note: "Redacted samples & reports", icon: Box, tone: "amber" },
  { label: "Policy cache", value: "KV", note: "60-second global cache", icon: Globe2, tone: "violet" },
  { label: "Async analysis", value: "Queues", note: "Retries + dead-letter queue", icon: Waypoints, tone: "mint" },
  { label: "Coordination", value: "Durable Objects", note: "Limits, counters, presence", icon: RadioTower, tone: "red" },
  { label: "Classification", value: "Workers AI", note: "Redacted threat enrichment", icon: Bot, tone: "cyan" },
];

export function SettingsView() {
  const [upstreams, setUpstreams] = useState<Upstream[]>([]);
  const [runtime, setRuntime] = useState<RuntimeStatus | null>(null);
  const [message, setMessage] = useState("");
  const [loadError, setLoadError] = useState("");
  const [copiedUpstream, setCopiedUpstream] = useState("");
  const [isCreating, setIsCreating] = useState(false);
  const createInFlight = useRef(false);

  async function load() {
    try {
      const [{ data }, runtimeStatus] = await Promise.all([
        apiFetch<{ data: Upstream[] }>("/v1/upstreams"),
        apiFetch<RuntimeStatus>("/v1/analytics/runtime"),
      ]);
      setUpstreams(data);
      setRuntime(runtimeStatus);
      setLoadError("");
    } catch (cause) {
      setRuntime(null);
      setLoadError(cause instanceof Error ? cause.message : "Runtime configuration is unavailable");
    }
  }

  useEffect(() => { void load(); }, []);

  async function copyUpstreamId(id: string) {
    await navigator.clipboard.writeText(id);
    setCopiedUpstream(id);
    window.setTimeout(() => setCopiedUpstream(""), 2_000);
  }

  async function createUpstream(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (createInFlight.current) return;
    createInFlight.current = true;
    setIsCreating(true);
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    try {
      await apiFetch("/v1/upstreams", {
        method: "POST",
        body: JSON.stringify({
          name: String(form.get("name")),
          baseUrl: String(form.get("baseUrl")),
          timeoutMs: Number(form.get("timeoutMs")),
          authHeaderName: "authorization",
          authValue: String(form.get("authValue") || "") || undefined,
        }),
      });
      setMessage("Upstream created. Its credential was encrypted before storage.");
      formElement.reset();
      await load();
    } catch (cause) {
      if (cause instanceof ApiError && cause.code === "upstream_name_conflict") {
        setMessage("That upstream is already registered. Use its route ID from the list above.");
        await load();
      } else {
        setMessage(cause instanceof Error ? cause.message : "Could not create upstream");
      }
    } finally {
      createInFlight.current = false;
      setIsCreating(false);
    }
  }

  return (
    <>
      <PageHeader eyebrow="Workspace configuration" title="Gateway settings" description="Manage trusted destinations, Cloudflare bindings, retention, and inspection behavior." actions={<span className={`data-mode ${runtime ? "live" : "demo"}`}><i /> {runtime ? `Live ${runtime.environment}` : "Configuration unavailable"}</span>} />
      {loadError ? <div className="inline-notice error" role="alert">{loadError}. Refresh after the gateway recovers.</div> : null}
      {message ? <div className="inline-notice" role="status" aria-live="polite">{message}</div> : null}
      <div className="settings-grid">
        <section className="panel settings-section upstream-section">
          <div className="panel-heading"><div><h2>Trusted upstreams</h2><p>Only registered public HTTPS origins can receive gateway traffic.</p></div><ServerCog size={19} /></div>
          <div className="upstream-list">{upstreams.map((upstream) => <article key={upstream.id}><span className="upstream-icon"><Cloud size={18} /></span><div><strong>{upstream.name}</strong><code>{upstream.base_url}</code><span className="upstream-route-id"><small>Route ID</small><code>{upstream.id}</code><button type="button" onClick={() => void copyUpstreamId(upstream.id)} aria-label={`Copy route ID for ${upstream.name}`}>{copiedUpstream === upstream.id ? <Check size={13} /> : <Copy size={13} />}</button></span></div><span><small>{upstream.timeout_ms / 1000}s timeout</small><StatusBadge value={upstream.status} /></span></article>)}</div>
          {upstreams.length === 0 ? <div className="table-empty compact-empty"><Cloud size={22} /><strong>No trusted upstreams</strong><span>Register a destination before routing gateway traffic.</span></div> : null}
          <form className="upstream-form" onSubmit={createUpstream}><h3><CirclePlus size={17} /> Add upstream</h3><div className="form-grid"><label>Name<input name="name" required minLength={2} placeholder="OpenAI production" /></label><label>HTTPS base URL<input name="baseUrl" required type="url" placeholder="https://api.example.com" /></label></div><div className="form-grid"><label>Authorization value<input name="authValue" type="password" autoComplete="off" placeholder="Optional; for example Bearer sk-…" /></label><label>Timeout<input name="timeoutMs" type="number" min="1000" max="120000" defaultValue="30000" /></label></div><button className="button secondary" type="submit" disabled={!runtime || isCreating}>{isCreating ? "Registering…" : "Register upstream"}</button></form>
        </section>
        <section className="panel settings-section runtime-section">
          <div className="panel-heading"><div><h2>Cloudflare runtime</h2><p>Resource bindings used by the production gateway.</p></div><span className="cf-mark">CF</span></div>
          <div className="binding-grid">{bindings.map((binding) => { const Icon = binding.icon; const enabled = binding.value === "R2" ? runtime?.artifactStorageEnabled : binding.value === "Workers AI" ? runtime?.aiEnabled : binding.value === "Queues" ? runtime?.queueEnabled : binding.value === "KV" ? runtime?.policyCacheEnabled : binding.value === "Durable Objects" ? runtime?.coordinatorEnabled : Boolean(runtime); return <article key={binding.value}><span className={`binding-icon ${binding.tone}`}><Icon size={17} /></span><div><small>{binding.label}</small><strong>{binding.value}</strong><p>{enabled === undefined ? "Status unavailable" : enabled ? binding.note : "Disabled in this environment"}</p></div><i className={enabled ? "" : "disabled"} /></article>; })}</div>
        </section>
        <section className="panel settings-section inspection-settings">
          <div className="panel-heading"><div><h2>Inspection controls</h2><p>Safe defaults loaded from Worker environment variables.</p></div></div>
          <div className="inspection-control"><span><strong>Asynchronous AI enrichment</strong><small>Classify redacted samples through Workers AI without adding upstream latency.</small></span><StatusBadge value={runtime?.aiEnabled ? "active" : "disabled"} /></div>
          <div className="inspection-control"><span><strong>Store blocked request samples</strong><small>Save redacted bodies in R2 with checksum metadata.</small></span><StatusBadge value={runtime?.artifactStorageEnabled ? "active" : "disabled"} /></div>
          <div className="inspection-control"><span><strong>Fail closed on oversized payloads</strong><small>Reject bodies larger than the one-megabyte inspection ceiling.</small></span><StatusBadge value="active" /></div>
        </section>
        <section className="panel settings-section deployment-card">
          <span className="deployment-icon"><Globe2 size={22} /></span><div><span className="eyebrow">Deployment</span><h2>Edge-ready configuration</h2><p>Wrangler files, migrations, queues, and observability are versioned with the repository.</p><div><StatusBadge value="configured" /><span>Compatibility date 2026-08-20</span></div></div>
        </section>
      </div>
    </>
  );
}
