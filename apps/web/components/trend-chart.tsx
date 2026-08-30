"use client";

interface Point {
  label: string;
  value: number;
  blocked: number;
}

export function TrendChart({ points }: { points: Point[] }) {
  const safePoints = points.length > 1 ? points : [{ label: "00:00", value: 0, blocked: 0 }, { label: "Now", value: 0, blocked: 0 }];
  const width = 760;
  const height = 220;
  const max = Math.max(...safePoints.map((point) => point.value), 1);
  const toPath = (key: "value" | "blocked") => safePoints
    .map((point, index) => {
      const x = (index / (safePoints.length - 1)) * width;
      const y = height - (point[key] / max) * (height - 20);
      return `${index === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
  const mainPath = toPath("value");
  const blockedPath = toPath("blocked");

  return (
    <div className="trend-chart">
      <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Requests and blocked threats over time" preserveAspectRatio="none">
        <defs>
          <linearGradient id="request-fill" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#53f1c3" stopOpacity=".2" /><stop offset="1" stopColor="#53f1c3" stopOpacity="0" /></linearGradient>
        </defs>
        {[0.25, 0.5, 0.75, 1].map((ratio) => <line key={ratio} x1="0" x2={width} y1={height * ratio} y2={height * ratio} className="grid-line" />)}
        <path d={`${mainPath} L${width},${height} L0,${height} Z`} fill="url(#request-fill)" />
        <path d={mainPath} className="request-line" />
        <path d={blockedPath} className="blocked-line" />
      </svg>
      <div className="chart-axis">{safePoints.filter((_, index) => index % Math.max(1, Math.floor(safePoints.length / 5)) === 0).map((point) => <span key={point.label}>{point.label}</span>)}</div>
    </div>
  );
}
