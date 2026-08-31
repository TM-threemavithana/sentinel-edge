"use client";

import { Ban, CheckCircle2, Download, Filter, Gauge, Search } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { apiFetch } from "@/lib/api";
import { PageHeader, StatusBadge } from "./page-header";

interface RequestEvent {
  id: string;
  request_id: string;
  method: string;
  path: string;
  status_code: number;
  decision: string;
  threat_categories_json: string;
  risk_score: number;
  country: string;
  latency_ms: number;
  request_bytes: number;
  created_at: string;
}

export function RequestsView() {
  const [requests, setRequests] = useState<RequestEvent[]>([]);
  const [query, setQuery] = useState("");
  const [decision, setDecision] = useState("all");
  const [loadError, setLoadError] = useState("");

  useEffect(() => {
    apiFetch<{ data: RequestEvent[] }>("/v1/analytics/requests?limit=100").then(({ data }) => {
      setRequests(data);
      setLoadError("");
    }).catch((cause) => setLoadError(cause instanceof Error ? cause.message : "Live events are unavailable"));
  }, []);

  const filtered = useMemo(() => requests.filter((request) => {
    const matchesDecision = decision === "all" || request.decision === decision;
    const needle = query.toLowerCase();
    return matchesDecision && (!needle || request.request_id.toLowerCase().includes(needle) || request.path.toLowerCase().includes(needle));
  }), [decision, query, requests]);

  const summary = useMemo(() => ({
    total: requests.length,
    blocked: requests.filter((request) => request.decision === "block").length,
    allowed: requests.filter((request) => request.decision === "allow").length,
    highRisk: requests.filter((request) => request.risk_score >= 75).length,
  }), [requests]);

  function exportCsv() {
    const header = "request_id,method,path,status,decision,risk,country,latency_ms,created_at";
    const rows = filtered.map((request) => [request.request_id, request.method, request.path, request.status_code, request.decision, request.risk_score, request.country, request.latency_ms, request.created_at].map((value) => JSON.stringify(value)).join(","));
    const url = URL.createObjectURL(new Blob([[header, ...rows].join("\n")], { type: "text/csv" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "sentinel-edge-requests.csv";
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <>
      <PageHeader eyebrow="Traffic intelligence" title="Request explorer" description="Investigate inspected requests, policy decisions, and threat signals." actions={<button className="button secondary" type="button" onClick={exportCsv} disabled={requests.length === 0}><Download size={15} /> Export CSV</button>} />
      {loadError ? <div className="inline-notice error" role="alert">{loadError}. Refresh the page after the gateway recovers.</div> : null}
      <section className="explorer-summary" aria-label="Request summary">
        <span><Gauge size={16} /><small>Visible traffic</small><strong>{summary.total}</strong></span>
        <span><CheckCircle2 size={16} /><small>Allowed</small><strong>{summary.allowed}</strong></span>
        <span><Ban size={16} /><small>Blocked</small><strong>{summary.blocked}</strong></span>
        <span><span className="summary-risk-dot" /><small>High risk</small><strong>{summary.highRisk}</strong></span>
      </section>
      <section className="panel explorer-panel">
        <div className="filter-bar">
          <label className="table-search"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search request ID or endpoint" aria-label="Search requests" /></label>
          <label className="select-wrap"><Filter size={15} /><select value={decision} onChange={(event) => setDecision(event.target.value)} aria-label="Filter by decision"><option value="all">All decisions</option><option value="allow">Allowed</option><option value="block">Blocked</option><option value="challenge">Challenged</option><option value="rate_limited">Rate limited</option></select></label>
          {query || decision !== "all" ? <button className="button ghost" type="button" onClick={() => { setQuery(""); setDecision("all"); }}>Clear filters</button> : null}
          <span className={`data-mode ${loadError ? "demo" : "live"}`}><i /> {loadError ? "Events unavailable" : `${filtered.length} live events`}</span>
        </div>
        <div className="table-wrap spacious"><table><thead><tr><th>Request ID</th><th>Endpoint</th><th>Threat signal</th><th>Risk</th><th>Decision</th><th>Status</th><th>Region</th><th>Latency</th><th>Time</th></tr></thead><tbody>{filtered.map((request) => { const threats = JSON.parse(request.threat_categories_json) as string[]; return <tr key={request.id}><td><strong className="mono">{request.request_id}</strong></td><td><span className={`method ${request.method.toLowerCase()}`}>{request.method}</span><span className="endpoint">{request.path}</span></td><td>{threats[0] ? <span className="threat-chip">{threats[0].replaceAll("_", " ")}</span> : <span className="muted">No signal</span>}</td><td><span className={`risk ${request.risk_score >= 75 ? "high" : request.risk_score >= 40 ? "medium" : "low"}`}>{request.risk_score}</span></td><td><StatusBadge value={request.decision} /></td><td><span className={request.status_code >= 400 ? "danger-text" : ""}>{request.status_code}</span></td><td>{request.country ?? "—"}</td><td>{request.latency_ms ?? 0} ms</td><td><time dateTime={request.created_at}>{new Date(request.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</time></td></tr>; })}</tbody></table></div>
        {filtered.length === 0 ? <div className="table-empty"><Search size={22} /><strong>No requests match these filters</strong><span>Clear the search or select another decision.</span></div> : null}
      </section>
    </>
  );
}
