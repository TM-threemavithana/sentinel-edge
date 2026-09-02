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

export function AuditView() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [query, setQuery] = useState("");
  const [loadError, setLoadError] = useState("");

  useEffect(() => {
    apiFetch<{ data: AuditEvent[] }>("/v1/analytics/audit?limit=100").then(({ data }) => {
      setEvents(data);
      setLoadError("");
    }).catch((cause) => setLoadError(cause instanceof Error ? cause.message : "The audit trail is unavailable"));
  }, []);

  const filtered = useMemo(() => events.filter((event) => `${event.action} ${event.resource_type} ${event.actor_id}`.toLowerCase().includes(query.toLowerCase())), [events, query]);

  function exportLog() {
    const url = URL.createObjectURL(new Blob([JSON.stringify(filtered, null, 2)], { type: "application/json" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "sentinel-edge-audit.json";
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <>
      <PageHeader eyebrow="Governance" title="Audit log" description="An activity trail for administrative and security-sensitive changes." actions={<><span className={`data-mode ${loadError ? "demo" : "live"}`}><i /> {loadError ? "Audit unavailable" : "Live audit trail"}</span><button className="button secondary" type="button" onClick={exportLog} disabled={events.length === 0}><Download size={15} /> Export JSON</button></>} />
      {loadError ? <div className="inline-notice error" role="alert">{loadError}. Refresh after the gateway recovers.</div> : null}
      <section className="audit-integrity"><FileClock size={20} /><div><strong>Workspace-scoped audit trail</strong><span>Administrative events are stored in D1 and returned only for the authenticated workspace.</span></div><em>{events.length} loaded</em></section>
      <section className="panel explorer-panel">
        <div className="filter-bar"><label className="table-search"><Search size={16} /><input name="audit-search" type="search" autoComplete="off" spellCheck={false} value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search action, actor, or resource…" aria-label="Search audit log" /></label><span className="data-mode live"><i /> {filtered.length} events</span></div>
        <div className="audit-timeline">{filtered.map((event) => <article key={event.id}><span className={`audit-icon ${event.actor_type}`}><FileClock size={15} /></span><div className="audit-main"><div><strong>{event.action.replaceAll(".", " · ")}</strong><span className="mono">{event.resource_id ?? "system"}</span></div><p><b>{event.actor_type === "system" ? "Sentinel system" : (event.actor_id || "User")}</b> acted on {event.resource_type}. <code>{JSON.stringify(JSON.parse(event.metadata_json))}</code></p><small>{event.request_id ? `Request ${event.request_id} · ` : ""}{new Date(event.created_at).toLocaleString([], { dateStyle: "medium", timeStyle: "medium" })}</small></div></article>)}</div>
        {filtered.length === 0 ? <div className="table-empty"><Search size={22} /><strong>No audit events match</strong><span>Clear the search to return to the full activity trail.</span></div> : null}
      </section>
    </>
  );
}
