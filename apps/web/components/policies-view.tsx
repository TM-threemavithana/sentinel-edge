"use client";

import { CirclePlus, ShieldCheck, Sparkles, X } from "lucide-react";
import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";
import { PageHeader, StatusBadge } from "./page-header";

interface Policy {
  id: string;
  name: string;
  description: string;
  priority: number;
  action: "allow" | "block" | "challenge" | "log";
  conditions_json: string;
  rate_limit_json: string | null;
  enabled: number;
  version: number;
  updated_at: string;
}

const SAMPLE: Policy[] = [
  { id: "pol_prompt", name: "Block prompt injection", description: "Reject instruction override and system prompt extraction attempts.", priority: 10, action: "block", conditions_json: '[{"field":"threat","operator":"equals","value":"prompt_injection"}]', rate_limit_json: null, enabled: 1, version: 3, updated_at: new Date().toISOString() },
  { id: "pol_critical", name: "Block critical application threats", description: "Stop SQL injection, SSRF, traversal, and credential exposure.", priority: 20, action: "block", conditions_json: '[{"field":"severity","operator":"at_least","value":"critical"}]', rate_limit_json: null, enabled: 1, version: 2, updated_at: new Date().toISOString() },
  { id: "pol_chat", name: "Chat completion budget", description: "Apply a per-key request ceiling to chat workloads.", priority: 100, action: "allow", conditions_json: '[{"field":"path","operator":"starts_with","value":"/v1/chat"}]', rate_limit_json: '{"requests":120,"windowSeconds":60,"keyBy":"api_key"}', enabled: 1, version: 1, updated_at: new Date().toISOString() },
  { id: "pol_geo", name: "Sensitive route geo challenge", description: "Challenge requests to management routes from outside approved regions.", priority: 150, action: "challenge", conditions_json: '[{"field":"path","operator":"starts_with","value":"/admin"}]', rate_limit_json: null, enabled: 0, version: 1, updated_at: new Date().toISOString() },
];

export function PoliciesView() {
  const [policies, setPolicies] = useState(SAMPLE);
  const [builderOpen, setBuilderOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");
  const [demoMode, setDemoMode] = useState(true);

  useEffect(() => {
    apiFetch<{ data: Policy[] }>("/v1/policies").then(({ data }) => {
      setPolicies(data);
      setDemoMode(false);
    }).catch(() => setDemoMode(true));
  }, []);

  async function toggle(policy: Policy) {
    const enabled = policy.enabled !== 1;
    setPolicies((items) => items.map((item) => item.id === policy.id ? { ...item, enabled: enabled ? 1 : 0 } : item));
    try {
      await apiFetch(`/v1/policies/${policy.id}`, { method: "PATCH", body: JSON.stringify({ enabled }) });
    } catch {
      setPolicies((items) => items.map((item) => item.id === policy.id ? policy : item));
    }
  }

  async function createPolicy(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setSaving(true);
    setMessage("");
    const field = String(form.get("field"));
    const payload = {
      name: String(form.get("name")),
      description: String(form.get("description")),
      priority: Number(form.get("priority")),
      action: String(form.get("action")),
      conditions: [{ field, operator: field === "severity" ? "at_least" : "starts_with", value: String(form.get("value")) }],
      enabled: true,
    };
    try {
      await apiFetch("/v1/policies", { method: "POST", body: JSON.stringify(payload) });
      setMessage("Policy created and propagated to the edge cache.");
      setBuilderOpen(false);
      const { data } = await apiFetch<{ data: Policy[] }>("/v1/policies");
      setPolicies(data);
    } catch (cause) {
      setMessage(cause instanceof Error ? cause.message : "Could not create policy");
    } finally {
      setSaving(false);
    }
  }

  return (
    <>
      <PageHeader eyebrow="Enforcement" title="Policy engine" description="Define ordered, tenant-aware rules that are evaluated before upstream traffic is released." actions={<><span className={`data-mode ${demoMode ? "demo" : "live"}`}><i /> {demoMode ? "Sample policies" : "Live configuration"}</span><button className="button primary" type="button" onClick={() => setBuilderOpen(true)}><CirclePlus size={16} /> New policy</button></>} />
      <section className="policy-summary"><article><ShieldCheck size={20} /><span><strong>{policies.filter((policy) => policy.enabled === 1).length} active policies</strong><small>All changes cached globally in under 60 seconds</small></span></article><article><Sparkles size={20} /><span><strong>Workers AI enrichment</strong><small>Asynchronous classification and report generation enabled</small></span><StatusBadge value="active" /></article></section>
      {message ? <div className="inline-notice">{message}</div> : null}
      <section className="panel policy-list">
        <div className="policy-list-head"><span>Order</span><span>Policy</span><span>Match</span><span>Action</span><span>Version</span><span>State</span></div>
        {policies.map((policy, index) => { const conditions = JSON.parse(policy.conditions_json) as Array<{ field: string; operator: string; value: string }>; return <article className={policy.enabled === 1 ? "" : "disabled"} key={policy.id}><span className="policy-order"><b>{index + 1}</b><small>Priority {policy.priority}</small></span><span className="policy-name"><strong>{policy.name}</strong><small>{policy.description}</small></span><span className="policy-condition"><code>{conditions[0]?.field}</code><small>{conditions[0]?.operator.replaceAll("_", " ")} {String(conditions[0]?.value)}</small>{policy.rate_limit_json ? <em>rate limit</em> : null}</span><span><StatusBadge value={policy.action} /></span><span className="mono">v{policy.version}</span><span><button type="button" className={`toggle ${policy.enabled === 1 ? "on" : ""}`} onClick={() => toggle(policy)} aria-label={`${policy.enabled === 1 ? "Disable" : "Enable"} ${policy.name}`} aria-pressed={policy.enabled === 1}><i /></button></span></article>; })}
        {policies.length === 0 ? <div className="table-empty"><ShieldCheck size={22} /><strong>No policies configured</strong><span>Create a policy to begin evaluating gateway traffic.</span></div> : null}
      </section>
      {builderOpen ? <div className="modal-backdrop"><section className="modal" role="dialog" aria-modal="true" aria-labelledby="builder-title"><header><div><span className="eyebrow">Rule builder</span><h2 id="builder-title">Create an edge policy</h2></div><button className="icon-button" type="button" onClick={() => setBuilderOpen(false)} aria-label="Close"><X size={18} /></button></header><form onSubmit={createPolicy}><label>Policy name<input name="name" required minLength={3} placeholder="Protect admin routes" /></label><label>Description<input name="description" required placeholder="Explain why this policy exists" /></label><div className="form-grid"><label>Priority<input name="priority" type="number" min="1" defaultValue="200" required /></label><label>Action<select name="action" defaultValue="block"><option value="block">Block</option><option value="challenge">Challenge</option><option value="log">Log</option><option value="allow">Allow</option></select></label></div><div className="form-grid"><label>Condition field<select name="field" defaultValue="path"><option value="path">Path starts with</option><option value="severity">Severity at least</option></select></label><label>Value<input name="value" defaultValue="/admin" required /></label></div><footer><button className="button ghost" type="button" onClick={() => setBuilderOpen(false)}>Cancel</button><button className="button primary" type="submit" disabled={saving}>{saving ? "Publishing…" : "Create policy"}</button></footer></form></section></div> : null}
    </>
  );
}
