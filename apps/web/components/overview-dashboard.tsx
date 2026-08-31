"use client";

import { Activity, Ban, Clock3, RefreshCw, ShieldAlert, ShieldCheck, Zap } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { apiFetch } from "@/lib/api";
import { PageHeader, StatusBadge } from "./page-header";
import { TrendChart } from "./trend-chart";

interface OverviewData {
  summary: {
    totalRequests: number;
    blocked: number;
    rateLimited: number;
    averageLatency: number;
    averageRisk: number;
  };
  series: Array<{ bucket: string; requests: number; blocked: number }>;
  topThreats: Array<{ category: string; count: number }>;
  recent: Array<{ request_id: string; method: string; path: string; country: string | null; risk_score: number; decision: string; latency_ms: number; created_at: string }>;
  capabilities: { activePolicies: number; aiEnabled: boolean; artifactStorageEnabled: boolean };
}

function number(value: number): string {
  return new Intl.NumberFormat("en-US", { notation: value >= 100_000 ? "compact" : "standard", maximumFractionDigits: 1 }).format(value);
}

export function OverviewDashboard() {
  const [data, setData] = useState<OverviewData | null>(null);
  const [live, setLive] = useState({ requestsPerMinute: 0, activeSessions: 0 });
  const [loadError, setLoadError] = useState("");
  const [refreshing, setRefreshing] = useState(false);

  async function refresh() {
    setRefreshing(true);
    setLoadError("");
    try {
      const [overview, snapshot] = await Promise.all([
        apiFetch<any>("/v1/analytics/overview"),
        apiFetch<any>("/v1/analytics/live"),
      ]);
      setData({
        summary: {
           totalRequests: overview.summary.total_requests || 0,
           blocked: overview.summary.blocked || 0,
           rateLimited: overview.summary.rate_limited || 0,
           averageLatency: overview.summary.average_latency || 0,
           averageRisk: overview.summary.average_risk || 0,
        },
        series: overview.series,
        topThreats: overview.topThreats,
        recent: overview.recent,
        capabilities: overview.capabilities,
      });
      setLive({
        requestsPerMinute: snapshot.live?.requests || 0,
        activeSessions: snapshot.activeUsers || 0
      });
    } catch (cause) {
      setData(null);
      setLoadError(cause instanceof Error ? cause.message : "Live telemetry is unavailable");
    } finally {
      setRefreshing(false);
    }
  }

  useEffect(() => {
    void refresh();
    
    const source = new EventSource("/api/backend/v1/analytics/live/stream", { withCredentials: true });
    
    source.onmessage = (event) => {
      try {
        const snapshot = JSON.parse(event.data);
        setLive({
          requestsPerMinute: snapshot.live?.requests || 0,
          activeSessions: snapshot.activeUsers || 0
        });
      } catch {}
    };
    
    return () => source.close();
  }, []);

  const chartPoints = useMemo(() => (data?.series ?? []).map((point) => ({
    label: point.bucket.includes("T") ? point.bucket.slice(11, 16) : point.bucket,
    value: Number(point.requests),
    blocked: Number(point.blocked),
  })), [data?.series]);

  const summary = data?.summary ?? { totalRequests: 0, blocked: 0, rateLimited: 0, averageLatency: 0, averageRisk: 0 };

  const stats = [
    { label: "Requests inspected", value: number(summary.totalRequests), icon: Activity, tone: "mint" },
    { label: "Threats blocked", value: number(summary.blocked), icon: Ban, tone: "red" },
    { label: "Rate limited", value: number(summary.rateLimited), icon: Zap, tone: "amber" },
    { label: "Edge latency", value: `${summary.averageLatency.toFixed(1)} ms`, icon: Clock3, tone: "blue" },
  ];

  return (
    <>
      <PageHeader
        eyebrow="Security operations"
        title="Threat posture"
        description="Monitor policy outcomes, emerging threats, and gateway performance across your perimeter."
        actions={<><span className={`data-mode ${loadError ? "demo" : "live"}`}><i /> {loadError ? "Telemetry unavailable" : data ? "Live gateway" : "Loading live data"}</span><button className="button secondary" type="button" onClick={refresh} disabled={refreshing}><RefreshCw size={15} className={refreshing ? "spin" : ""} /> Refresh</button></>}
      />
      {loadError ? <div className="inline-notice error" role="alert">{loadError}. Refresh after the gateway is available.</div> : null}
      <section className="ops-brief" aria-label="Current protection status">
        <div className="ops-brief-status"><span className="ops-brief-icon"><ShieldCheck size={21} /></span><div><span className="eyebrow">Current status</span><h2>{data ? "Live telemetry connected" : "Waiting for gateway telemetry"}</h2><p>{data ? `${data.capabilities.activePolicies} active policies are evaluating gateway traffic.` : "No operational claims are shown until live data is available."}</p></div></div>
        <div className="ops-brief-metrics"><span><small>Active policies</small><strong>{data?.capabilities.activePolicies ?? "—"}</strong></span><span><small>Current throughput</small><strong>{number(live.requestsPerMinute)}<span> req/min</span></strong></span><span><small>Average risk</small><strong>{data ? summary.averageRisk.toFixed(1) : "—"}<span> / 100</span></strong></span></div>
      </section>
      <section className="stat-grid" aria-label="24 hour security summary">
        {stats.map((stat) => {
          const Icon = stat.icon;
          return <article className={`stat-card ${stat.tone}`} key={stat.label}><div className={`stat-icon ${stat.tone}`}><Icon size={18} /></div><span>{stat.label}<small>Last 24 hours</small></span><strong>{data ? stat.value : "—"}</strong></article>;
        })}
      </section>
      <section className="overview-grid">
        <article className="panel traffic-panel">
          <div className="panel-heading"><div><span className="panel-kicker">24-hour activity</span><h2>Traffic & decisions</h2><p>Requests inspected at the edge</p></div><div className="chart-legend"><span><i className="request-dot" /> Requests</span><span><i className="blocked-dot" /> Blocked</span></div></div>
          <TrendChart points={chartPoints} />
        </article>
        <article className="panel protection-panel">
          <div className="panel-heading"><div><span className="panel-kicker">Coverage</span><h2>Enforcement configuration</h2><p>Verified runtime capabilities</p></div><ShieldAlert size={18} /></div>
          <div className="score-ring" style={{ "--score": data?.capabilities.activePolicies ? "100%" : "0%" } as React.CSSProperties}><div><strong>{data?.capabilities.activePolicies ?? "—"}</strong><small>active policies</small></div></div>
          <div className="score-items"><span><i className={data?.capabilities.activePolicies ? "good" : "warn"} /> Policy enforcement<strong>{data ? (data.capabilities.activePolicies > 0 ? "Configured" : "No policies") : "Unknown"}</strong></span><span><i className={data?.capabilities.aiEnabled ? "good" : "warn"} /> AI inspection<strong>{data ? (data.capabilities.aiEnabled ? "Active" : "Disabled") : "Unknown"}</strong></span><span><i className={data?.capabilities.artifactStorageEnabled ? "good" : "warn"} /> Artifact storage<strong>{data ? (data.capabilities.artifactStorageEnabled ? "Active" : "Disabled") : "Unknown"}</strong></span></div>
          <div className="live-strip"><span><i /> {number(live.requestsPerMinute)} req/min</span><span>{live.activeSessions} active sessions</span></div>
        </article>
      </section>
      <section className="lower-grid">
        <article className="panel recent-panel">
          <div className="panel-heading"><div><h2>Recent decisions</h2><p>Latest requests evaluated by the gateway</p></div><a href="/dashboard/requests">View all requests →</a></div>
          <div className="table-wrap"><table><thead><tr><th>Request</th><th>Endpoint</th><th>Region</th><th>Risk</th><th>Decision</th><th>Latency</th></tr></thead><tbody>{(data?.recent ?? []).map((item) => <tr key={item.request_id}><td><strong className="mono">{item.request_id}</strong><small>{new Date(item.created_at).toLocaleTimeString()}</small></td><td><span className={`method ${item.method.toLowerCase()}`}>{item.method}</span><span className="endpoint">{item.path}</span></td><td>{item.country ?? "—"}</td><td><span className={`risk ${item.risk_score >= 75 ? "high" : item.risk_score >= 40 ? "medium" : "low"}`}>{item.risk_score}</span></td><td><StatusBadge value={item.decision} /></td><td>{item.latency_ms} ms</td></tr>)}</tbody></table></div>
          {data && data.recent.length === 0 ? <div className="table-empty compact-empty"><Activity size={22} /><strong>No requests yet</strong><span>Live gateway events will appear here.</span></div> : null}
        </article>
        <article className="panel threat-panel">
          <div className="panel-heading"><div><h2>Top threat signals</h2><p>Last 7 days</p></div></div>
          <div className="threat-list">{(data?.topThreats ?? []).map((threat, index) => { const max = Number(data?.topThreats[0]?.count ?? 1); return <div key={threat.category}><span><i>{index + 1}</i>{threat.category.replaceAll("_", " ")}</span><strong>{number(Number(threat.count))}</strong><div><b style={{ width: `${(Number(threat.count) / max) * 100}%` }} /></div></div>; })}</div>
          {data && data.topThreats.length === 0 ? <div className="table-empty compact-empty"><ShieldCheck size={22} /><strong>No threat signals</strong><span>No threats were recorded in the current window.</span></div> : null}
        </article>
      </section>
    </>
  );
}
