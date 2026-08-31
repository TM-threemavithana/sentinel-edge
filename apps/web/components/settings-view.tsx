"use client";

import { Bot, Box, CirclePlus, Cloud, Database, Globe2, RadioTower, ServerCog, Waypoints } from "lucide-react";
import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";
import { PageHeader, StatusBadge } from "./page-header";

interface Upstream {
  id: string;
  name: string;
  base_url: string;
  timeout_ms: number;
  status: string;
  created_at: string;
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
  const [upstreams, setUpstreams] = useState<Upstream[]>([
    { id: "ups_echo", name: "Safe echo service", base_url: "https://httpbin.org", timeout_ms: 15000, status: "active", created_at: new Date().toISOString() },
  ]);
  const [message, setMessage] = useState("");
  const [demoMode, setDemoMode] = useState(true);

  async function load() {
    try {
      const { data } = await apiFetch<{ data: Upstream[] }>("/v1/upstreams");
      setUpstreams(data);
      setDemoMode(false);
    } catch {
      setDemoMode(true);
    }
  }

  useEffect(() => { void load(); }, []);

  async function createUpstream(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
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
      event.currentTarget.reset();
      await load();
    } catch (cause) {
      setMessage(cause instanceof Error ? cause.message : "Could not create upstream");
    }
  }

  return (
    <>
      <PageHeader eyebrow="Workspace configuration" title="Gateway settings" description="Manage trusted destinations, Cloudflare bindings, retention, and inspection behavior." actions={<span className={`data-mode ${demoMode ? "demo" : "live"}`}><i /> {demoMode ? "Preview configuration" : "Live configuration"}</span>} />
      {message ? <div className="inline-notice">{message}</div> : null}
      <div className="settings-grid">
        <section className="panel settings-section upstream-section">
          <div className="panel-heading"><div><h2>Trusted upstreams</h2><p>Only registered public HTTPS origins can receive gateway traffic.</p></div><ServerCog size={19} /></div>
          <div className="upstream-list">{upstreams.map((upstream) => <article key={upstream.id}><span className="upstream-icon"><Cloud size={18} /></span><div><strong>{upstream.name}</strong><code>{upstream.base_url}</code></div><span><small>{upstream.timeout_ms / 1000}s timeout</small><StatusBadge value={upstream.status} /></span></article>)}</div>
          {upstreams.length === 0 ? <div className="table-empty compact-empty"><Cloud size={22} /><strong>No trusted upstreams</strong><span>Register a destination before routing gateway traffic.</span></div> : null}
          <form className="upstream-form" onSubmit={createUpstream}><h3><CirclePlus size={17} /> Add upstream</h3><div className="form-grid"><label>Name<input name="name" required minLength={2} placeholder="OpenAI production" /></label><label>HTTPS base URL<input name="baseUrl" required type="url" placeholder="https://api.example.com" /></label></div><div className="form-grid"><label>Bearer credential<input name="authValue" type="password" autoComplete="off" placeholder="Optional; encrypted at rest" /></label><label>Timeout<input name="timeoutMs" type="number" min="1000" max="120000" defaultValue="30000" /></label></div><button className="button secondary" type="submit">Register upstream</button></form>
        </section>
        <section className="panel settings-section runtime-section">
          <div className="panel-heading"><div><h2>Cloudflare runtime</h2><p>Resource bindings used by the production gateway.</p></div><span className="cf-mark">CF</span></div>
          <div className="binding-grid">{bindings.map((binding) => { const Icon = binding.icon; return <article key={binding.value}><span className={`binding-icon ${binding.tone}`}><Icon size={17} /></span><div><small>{binding.label}</small><strong>{binding.value}</strong><p>{binding.note}</p></div><i /></article>; })}</div>
        </section>
        <section className="panel settings-section inspection-settings">
          <div className="panel-heading"><div><h2>Inspection controls</h2><p>Safe defaults loaded from Worker environment variables.</p></div></div>
          <div className="inspection-control"><span><strong>Asynchronous AI enrichment</strong><small>Classify redacted samples through Workers AI without adding upstream latency.</small></span><StatusBadge value="active" /></div>
          <div className="inspection-control"><span><strong>Store blocked request samples</strong><small>Save redacted bodies in R2 for 30 days with checksum metadata.</small></span><StatusBadge value="active" /></div>
          <div className="inspection-control"><span><strong>Fail closed on oversized payloads</strong><small>Reject bodies larger than the one-megabyte inspection ceiling.</small></span><StatusBadge value="active" /></div>
        </section>
        <section className="panel settings-section deployment-card">
          <span className="deployment-icon"><Globe2 size={22} /></span><div><span className="eyebrow">Deployment</span><h2>Edge-ready configuration</h2><p>Wrangler files, migrations, queues, and observability are versioned with the repository.</p><div><StatusBadge value="configured" /><span>Compatibility date 2026-08-20</span></div></div>
        </section>
      </div>
    </>
  );
}
