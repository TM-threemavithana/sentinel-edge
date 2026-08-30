"use client";

export default function ErrorPage({ reset }: { reset: () => void }) {
  return (
    <main className="center-page">
      <div className="empty-card">
        <span className="eyebrow danger-text">Console error</span>
        <h1>The control plane hit an unexpected fault.</h1>
        <p>The gateway continues processing traffic. Retry this view when you’re ready.</p>
        <button className="button primary" type="button" onClick={reset}>Retry view</button>
      </div>
    </main>
  );
}
