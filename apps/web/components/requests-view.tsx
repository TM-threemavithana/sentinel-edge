"use client";

import { Download, Filter, Search, SlidersHorizontal } from "lucide-react";
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

const SAMPLE: RequestEvent[] = [
  ["8Y2AF", "POST", "/v1/chat/completions", 403, "block", "prompt_injection", 96, "US", 7],
  ["1K9QP", "POST", "/v1/embeddings", 200, "allow", "", 12, "DE", 11],
  ["4M7LC", "GET", "/v1/models", 200, "allow", "", 4, "SG", 6],
  ["9R3VX", "POST", "/v1/chat/completions", 403, "challenge", "secret_exposure", 78, "GB", 9],
  ["6T1NB", "POST", "/v1/responses", 200, "allow", "", 8, "AU", 14],
  ["3D8JH", "POST", "/v1/chat/completions", 429, "rate_limited", "", 22, "BR", 5],
  ["7P5WS", "POST", "/v1/files", 403, "block", "malicious_file", 91, "NL", 18],
  ["2A4FE", "GET", "/v1/usage", 200, "allow", "", 2, "CA", 8],
].map((row, index) => ({
  id: `evt_${row[0]}`, request_id: `req_${row[0]}`, method: String(row[1]), path: String(row[2]),
  status_code: Number(row[3]), decision: String(row[4]),
  threat_categories_json: row[5] ? JSON.stringify([row[5]]) : "[]", risk_score: Number(row[6]),
  country: String(row[7]), latency_ms: Number(row[8]), request_bytes: 1200 + index * 491,
  created_at: new Date(Date.now() - index * 28_000).toISOString(),
}));

export function RequestsView() {
  const [requests, setRequests] = useState(SAMPLE);
  const [query, setQuery] = useState("");
  const [decision, setDecision] = useState("all");
  const [demoMode, setDemoMode] = useState(true);

  useEffect(() => {
    apiFetch<{ data: RequestEvent[] }>("/v1/analytics/requests?limit=100").then(({ data }) => {
      if (data.length > 0) setRequests(data);
      setDemoMode(data.length === 0);
    }).catch(() => setDemoMode(true));
  }, []);

  const filtered = useMemo(() => requests.filter((request) => {
    const matchesDecision = decision === "all" || request.decision === decision;
    const needle = query.toLowerCase();
    return matchesDecision && (!needle || request.request_id.toLowerCase().includes(needle) || request.path.toLowerCase().includes(needle));
  }), [decision, query, requests]);

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
      <PageHeader eyebrow="Traffic intelligence" title="Request explorer" description="Investigate inspected requests, policy decisions, and threat signals." actions={<button className="button secondary" type="button" onClick={exportCsv}><Download size={15} /> Export CSV</button>} />
      <section className="panel explorer-panel">
        <div className="filter-bar">
          <label className="table-search"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search request ID or endpoint" aria-label="Search requests" /></label>
          <label className="select-wrap"><Filter size={15} /><select value={decision} onChange={(event) => setDecision(event.target.value)} aria-label="Filter by decision"><option value="all">All decisions</option><option value="allow">Allowed</option><option value="block">Blocked</option><option value="challenge">Challenged</option><option value="rate_limited">Rate limited</option></select></label>
          <button className="button ghost" type="button"><SlidersHorizontal size={15} /> More filters</button>
          <span className={`data-mode ${demoMode ? "demo" : "live"}`}><i /> {demoMode ? "Sample dataset" : `${filtered.length} live events`}</span>
        </div>
        <div className="table-wrap spacious"><table><thead><tr><th>Request ID</th><th>Endpoint</th><th>Threat signal</th><th>Risk</th><th>Decision</th><th>Status</th><th>Region</th><th>Latency</th><th>Time</th></tr></thead><tbody>{filtered.map((request) => { const threats = JSON.parse(request.threat_categories_json) as string[]; return <tr key={request.id}><td><strong className="mono">{request.request_id}</strong></td><td><span className={`method ${request.method.toLowerCase()}`}>{request.method}</span><span className="endpoint">{request.path}</span></td><td>{threats[0] ? <span className="threat-chip">{threats[0].replaceAll("_", " ")}</span> : <span className="muted">No signal</span>}</td><td><span className={`risk ${request.risk_score >= 75 ? "high" : request.risk_score >= 40 ? "medium" : "low"}`}>{request.risk_score}</span></td><td><StatusBadge value={request.decision} /></td><td><span className={request.status_code >= 400 ? "danger-text" : ""}>{request.status_code}</span></td><td>{request.country ?? "—"}</td><td>{request.latency_ms ?? 0} ms</td><td><time dateTime={request.created_at}>{new Date(request.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</time></td></tr>; })}</tbody></table></div>
        {filtered.length === 0 ? <div className="table-empty"><Search size={22} /><strong>No requests match these filters</strong><span>Clear the search or select another decision.</span></div> : null}
      </section>
    </>
  );
}
