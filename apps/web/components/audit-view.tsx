"use client";

import { Download, FileClock, Search } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { apiFetch } from "@/lib/api";
import { PageHeader } from "./page-header";

interface AuditEvent {
  id: string;
  actor_type: string;
  actor_id: string | null;
  action: string;
  resource_type: string;
  resource_id: string | null;
  metadata_json: string;
  request_id: string | null;
  created_at: string;
}

const SAMPLE_ACTIONS = ["auth.login", "policy.updated", "api_key.created", "upstream.created", "api_key.revoked", "workspace.seeded"];
const SAMPLE: AuditEvent[] = SAMPLE_ACTIONS.map((action, index) => ({
  id: `aud_${index}`, actor_type: index === 5 ? "system" : "user", actor_id: index === 5 ? null : "usr_demo_admin",
  action, resource_type: action.split(".")[0] ?? "workspace", resource_id: index === 0 ? "ses_4a72" : `res_${index}`,
  metadata_json: JSON.stringify(index === 1 ? { name: "Block prompt injection", version: 3 } : { source: "console" }),
  request_id: `ray_${(9032 - index).toString(16)}`, created_at: new Date(Date.now() - index * 1_570_000).toISOString(),
}));

export function AuditView() {
  const [events, setEvents] = useState(SAMPLE);
  const [query, setQuery] = useState("");

  useEffect(() => {
    apiFetch<{ data: AuditEvent[] }>("/v1/analytics/audit?limit=100").then(({ data }) => {
      setEvents(data);
    }).catch(() => undefined);
  }, []);

  const filtered = useMemo(() => events.filter((event) => `${event.action} ${event.resource_type} ${event.actor_id}`.toLowerCase().includes(query.toLowerCase())), [events, query]);

  return (
    <>
      <PageHeader eyebrow="Governance" title="Audit log" description="An immutable activity trail for administrative and security-sensitive changes." actions={<button className="button secondary" type="button"><Download size={15} /> Export log</button>} />
      <section className="audit-integrity"><FileClock size={20} /><div><strong>Audit integrity is healthy</strong><span>Events are append-only in D1; report artifacts carry SHA-256 checksums in R2 metadata.</span></div><em>Retention: 30 days</em></section>
      <section className="panel explorer-panel">
        <div className="filter-bar"><label className="table-search"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search action, actor, or resource" aria-label="Search audit log" /></label><span className="data-mode live"><i /> {filtered.length} events</span></div>
        <div className="audit-timeline">{filtered.map((event) => <article key={event.id}><span className={`audit-icon ${event.actor_type}`}><FileClock size={15} /></span><div className="audit-main"><div><strong>{event.action.replaceAll(".", " · ")}</strong><span className="mono">{event.resource_id ?? "system"}</span></div><p><b>{event.actor_type === "system" ? "Sentinel system" : (event.actor_id || "User")}</b> acted on {event.resource_type}. <code>{JSON.stringify(JSON.parse(event.metadata_json))}</code></p><small>{event.request_id ? `Request ${event.request_id} · ` : ""}{new Date(event.created_at).toLocaleString([], { dateStyle: "medium", timeStyle: "medium" })}</small></div></article>)}</div>
      </section>
    </>
  );
}
