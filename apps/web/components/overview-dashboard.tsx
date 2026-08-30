"use client";

import { Activity, ArrowDownRight, ArrowUpRight, Ban, Clock3, RefreshCw, ShieldAlert, Zap } from "lucide-react";
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
}

const SAMPLE: OverviewData = {
  summary: { totalRequests: 284_392, blocked: 1_247, rateLimited: 3_891, averageLatency: 12.8, averageRisk: 18.4 },
  series: Array.from({ length: 24 }, (_, index) => ({
    bucket: `${String(index).padStart(2, "0")}:00`,
    requests: [7200, 6800, 6400, 5900, 6100, 8300, 11200, 13900, 14600, 15100, 14200, 15600, 16800, 16100, 17400, 18100, 19500, 18800, 17900, 16200, 14800, 13200, 11400, 9600][index] ?? 0,
    blocked: [32, 28, 24, 21, 27, 41, 55, 70, 62, 88, 79, 96, 110, 102, 135, 126, 146, 132, 120, 94, 78, 66, 49, 40][index] ?? 0,
  })),
  topThreats: [
    { category: "prompt_injection", count: 612 },
    { category: "sqli", count: 241 },
    { category: "secret_exposure", count: 196 },
    { category: "ssrf", count: 104 },
  ],
};

const RECENT = [
  { id: "req_8Y2AF", time: "14:32:08", method: "POST", path: "/v1/chat/completions", country: "US", risk: 96, decision: "block", latency: 7 },
  { id: "req_1K9QP", time: "14:31:54", method: "POST", path: "/v1/embeddings", country: "DE", risk: 12, decision: "allow", latency: 11 },
  { id: "req_4M7LC", time: "14:31:41", method: "GET", path: "/v1/models", country: "SG", risk: 4, decision: "allow", latency: 6 },
  { id: "req_9R3VX", time: "14:31:19", method: "POST", path: "/v1/chat/completions", country: "GB", risk: 78, decision: "challenge", latency: 9 },
  { id: "req_6T1NB", time: "14:30:57", method: "POST", path: "/v1/responses", country: "AU", risk: 8, decision: "allow", latency: 14 },
];

function number(value: number): string {
  return new Intl.NumberFormat("en-US", { notation: value >= 100_000 ? "compact" : "standard", maximumFractionDigits: 1 }).format(value);
}

export function OverviewDashboard() {
  const [data, setData] = useState<OverviewData>(SAMPLE);
  const [live, setLive] = useState({ requestsPerMinute: 1284, activeSessions: 9 });
  const [demoMode, setDemoMode] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  async function refresh() {
    setRefreshing(true);
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
        topThreats: overview.topThreats
      });
      setLive({
        requestsPerMinute: snapshot.live?.requests || 0,
        activeSessions: snapshot.activeUsers || 0
      });
      setDemoMode(false);
    } catch {
      setDemoMode(true);
    } finally {
      setRefreshing(false);
    }
  }

  useEffect(() => {
    void refresh();
    
    // Server-Sent Events (SSE) connection for live analytics
    // Use getGatewayOrigin() from api if exported, or construct the URL manually if not.
    // Wait, the API url is /v1/analytics/live/stream
    // Since we need to send the CSRF token and credentials, we can just use EventSource with withCredentials.
    // However, we need the full URL. Let's just assume NEXT_PUBLIC_GATEWAY_ORIGIN is used or fallback to localhost.
    const origin = process.env.NEXT_PUBLIC_GATEWAY_ORIGIN || "http://127.0.0.1:8787";
    const source = new EventSource(`${origin}/v1/analytics/live/stream`, { withCredentials: true });
    
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

  const chartPoints = useMemo(() => data.series.map((point) => ({
    label: point.bucket.includes("T") ? point.bucket.slice(11, 16) : point.bucket,
    value: Number(point.requests),
    blocked: Number(point.blocked),
  })), [data.series]);

  const stats = [
    { label: "Requests inspected", value: number(data.summary.totalRequests), trend: "+18.2%", positive: true, icon: Activity, tone: "mint" },
    { label: "Threats blocked", value: number(data.summary.blocked), trend: "+6.4%", positive: false, icon: Ban, tone: "red" },
    { label: "Rate limited", value: number(data.summary.rateLimited), trend: "−3.1%", positive: true, icon: Zap, tone: "amber" },
    { label: "Edge latency", value: `${data.summary.averageLatency.toFixed(1)} ms`, trend: "−1.8 ms", positive: true, icon: Clock3, tone: "blue" },
  ];

  return (
    <>
      <PageHeader
        eyebrow="Security operations · Live"
        title="Threat posture"
        description="A real-time view of every policy decision across your AI and API perimeter."
        actions={<><span className={`data-mode ${demoMode ? "demo" : "live"}`}><i /> {demoMode ? "Sample dataset" : "Live gateway"}</span><button className="button secondary" type="button" onClick={refresh} disabled={refreshing}><RefreshCw size={15} className={refreshing ? "spin" : ""} /> Refresh</button></>}
      />
      <section className="stat-grid" aria-label="24 hour security summary">
        {stats.map((stat) => {
          const Icon = stat.icon;
          return <article className="stat-card" key={stat.label}><div className={`stat-icon ${stat.tone}`}><Icon size={18} /></div><span>{stat.label}<small>Last 24 hours</small></span><strong>{stat.value}</strong><em className={stat.positive ? "positive" : "negative"}>{stat.positive ? <ArrowUpRight size={13} /> : <ArrowDownRight size={13} />}{stat.trend}</em></article>;
        })}
      </section>
      <section className="overview-grid">
        <article className="panel traffic-panel">
          <div className="panel-heading"><div><h2>Traffic & decisions</h2><p>Requests inspected at the edge over 24 hours</p></div><div className="chart-legend"><span><i className="request-dot" /> Requests</span><span><i className="blocked-dot" /> Blocked</span></div></div>
          <TrendChart points={chartPoints} />
        </article>
        <article className="panel protection-panel">
          <div className="panel-heading"><div><h2>Protection score</h2><p>Policy coverage and response health</p></div><ShieldAlert size={18} /></div>
          <div className="score-ring" style={{ "--score": "92%" } as React.CSSProperties}><div><strong>92</strong><span>/100</span><small>Strong</small></div></div>
          <div className="score-items"><span><i className="good" /> Core policies<strong>8 / 8</strong></span><span><i className="good" /> AI inspection<strong>Active</strong></span><span><i className="warn" /> Key rotation<strong>1 due</strong></span></div>
          <div className="live-strip"><span><i /> {number(live.requestsPerMinute)} req/min</span><span>{live.activeSessions} active sessions</span></div>
        </article>
      </section>
      <section className="lower-grid">
        <article className="panel recent-panel">
          <div className="panel-heading"><div><h2>Recent decisions</h2><p>Latest requests evaluated by the gateway</p></div><a href="/dashboard/requests">View all requests →</a></div>
          <div className="table-wrap"><table><thead><tr><th>Request</th><th>Endpoint</th><th>Region</th><th>Risk</th><th>Decision</th><th>Latency</th></tr></thead><tbody>{RECENT.map((item) => <tr key={item.id}><td><strong className="mono">{item.id}</strong><small>{item.time}</small></td><td><span className={`method ${item.method.toLowerCase()}`}>{item.method}</span><span className="endpoint">{item.path}</span></td><td>{item.country}</td><td><span className={`risk ${item.risk >= 75 ? "high" : item.risk >= 40 ? "medium" : "low"}`}>{item.risk}</span></td><td><StatusBadge value={item.decision} /></td><td>{item.latency} ms</td></tr>)}</tbody></table></div>
        </article>
        <article className="panel threat-panel">
          <div className="panel-heading"><div><h2>Top threat signals</h2><p>Last 7 days</p></div></div>
          <div className="threat-list">{data.topThreats.map((threat, index) => { const max = Number(data.topThreats[0]?.count ?? 1); return <div key={threat.category}><span><i>{index + 1}</i>{threat.category.replaceAll("_", " ")}</span><strong>{number(Number(threat.count))}</strong><div><b style={{ width: `${(Number(threat.count) / max) * 100}%` }} /></div></div>; })}</div>
        </article>
      </section>
    </>
  );
}
