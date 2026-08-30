import Link from "next/link";

export default function NotFound() {
  return (
    <main className="center-page">
      <div className="empty-card">
        <span className="eyebrow">404 · Route not found</span>
        <h1>This surface is outside the perimeter.</h1>
        <p>Return to the security overview to continue monitoring traffic.</p>
        <Link className="button primary" href="/dashboard">Return to dashboard</Link>
      </div>
    </main>
  );
}
