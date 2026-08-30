"use client";

import {
  Activity,
  Bell,
  BookOpenText,
  ChevronDown,
  FileClock,
  Gauge,
  KeyRound,
  LogOut,
  Menu,
  Search,
  Settings,
  ShieldCheck,
  SlidersHorizontal,
  X,
} from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";
import { Brand } from "./brand";

const navigation = [
  { href: "/dashboard", label: "Overview", icon: Gauge },
  { href: "/dashboard/requests", label: "Requests", icon: Activity },
  { href: "/dashboard/policies", label: "Policies", icon: SlidersHorizontal },
  { href: "/dashboard/api-keys", label: "API keys", icon: KeyRound },
  { href: "/dashboard/audit", label: "Audit log", icon: FileClock },
];

interface Viewer {
  displayName: string;
  email: string;
  workspaceName: string;
  role: "admin" | "analyst" | "viewer";
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [viewer, setViewer] = useState<Viewer | null>(null);
  const [menuOpen, setMenuOpen] = useState(false);

  useEffect(() => {
    let active = true;
    apiFetch<{ user: Viewer }>("/v1/auth/me")
      .then(({ user }) => {
        if (active) setViewer(user);
      })
      .catch(() => router.replace("/login"));
    return () => {
      active = false;
    };
  }, [router]);

  async function signOut() {
    await apiFetch("/v1/auth/logout", { method: "POST", body: "{}" }).catch(() => undefined);
    router.replace("/login");
  }

  return (
    <div className="app-frame">
      <aside className={`sidebar ${menuOpen ? "open" : ""}`}>
        <div className="sidebar-brand"><Brand /><button className="icon-button mobile-only" type="button" onClick={() => setMenuOpen(false)} aria-label="Close navigation"><X size={18} /></button></div>
        <div className="workspace-switcher">
          <span className="workspace-avatar">AC</span>
          <span><small>Workspace</small><strong>{viewer?.workspaceName ?? "Acme AI Platform"}</strong></span>
          <ChevronDown size={15} />
        </div>
        <nav className="primary-nav" aria-label="Main navigation">
          <span className="nav-label">Security operations</span>
          {navigation.map((item) => {
            const active = item.href === "/dashboard" ? pathname === item.href : pathname.startsWith(item.href);
            const Icon = item.icon;
            return (
              <Link className={active ? "active" : ""} href={item.href} key={item.href} onClick={() => setMenuOpen(false)}>
                <Icon size={17} />
                <span>{item.label}</span>
                {item.label === "Requests" ? <em>12</em> : null}
              </Link>
            );
          })}
          <span className="nav-label second">Manage</span>
          <Link className={pathname.startsWith("/dashboard/settings") ? "active" : ""} href="/dashboard/settings" onClick={() => setMenuOpen(false)}><Settings size={17} /><span>Settings</span></Link>
          <a href="https://developers.cloudflare.com/workers/" target="_blank" rel="noreferrer"><BookOpenText size={17} /><span>Documentation</span></a>
        </nav>
        <div className="security-state">
          <span className="pulse-dot" />
          <div><strong>All systems guarded</strong><small>7 edge regions active</small></div>
          <ShieldCheck size={18} />
        </div>
        <div className="sidebar-user">
          <span className="user-avatar">{viewer?.displayName.split(" ").map((part) => part[0]).join("").slice(0, 2) ?? "MC"}</span>
          <span><strong>{viewer?.displayName ?? "Maya Chen"}</strong><small>{viewer?.role ?? "admin"}</small></span>
          <button className="icon-button" type="button" onClick={signOut} aria-label="Sign out"><LogOut size={16} /></button>
        </div>
      </aside>
      {menuOpen ? <button className="sidebar-scrim" type="button" onClick={() => setMenuOpen(false)} aria-label="Close navigation" /> : null}
      <div className="main-column">
        <header className="topbar">
          <button className="icon-button mobile-only" type="button" onClick={() => setMenuOpen(true)} aria-label="Open navigation"><Menu size={19} /></button>
          <div className="command-search"><Search size={16} /><span>Search requests, policies, keys…</span><kbd>⌘ K</kbd></div>
          <div className="topbar-actions">
            <span className="environment-pill"><i /> Production</span>
            <button className="icon-button notification-button" type="button" aria-label="Notifications"><Bell size={18} /><b /></button>
          </div>
        </header>
        <main className="console-main">{children}</main>
      </div>
    </div>
  );
}
