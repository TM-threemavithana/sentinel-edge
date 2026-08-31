"use client";

import { Check, CirclePlus, Copy, KeyRound, Shield, Trash2, X } from "lucide-react";
import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";
import { PageHeader, StatusBadge } from "./page-header";

interface ApiKeyRecord {
  id: string;
  name: string;
  key_prefix: string;
  scopes_json: string;
  status: string;
  expires_at: string | null;
  last_used_at: string | null;
  created_at: string;
}

export function ApiKeysView() {
  const [keys, setKeys] = useState<ApiKeyRecord[]>([]);
  const [modalOpen, setModalOpen] = useState(false);
  const [revealedKey, setRevealedKey] = useState("");
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState("");
  const [loaded, setLoaded] = useState(false);

  async function load() {
    try {
      const { data } = await apiFetch<{ data: ApiKeyRecord[] }>("/v1/api-keys");
      setKeys(data);
      setLoaded(true);
    } catch {
      setLoaded(false);
      setError("Live credentials are unavailable");
    }
  }

  useEffect(() => { void load(); }, []);

  async function create(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    setError("");
    try {
      const result = await apiFetch<{ key: string }>("/v1/api-keys", {
        method: "POST",
        body: JSON.stringify({ name: String(data.get("name")), scopes: ["gateway:invoke"], expiresAt: null }),
      });
      setRevealedKey(result.key);
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not create API key");
    }
  }

  async function revoke(id: string) {
    if (!window.confirm("Revoke this key? Existing clients will immediately lose access.")) return;
    try {
      await apiFetch(`/v1/api-keys/${id}`, { method: "DELETE" });
      setKeys((items) => items.map((item) => item.id === id ? { ...item, status: "revoked" } : item));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not revoke key");
    }
  }

  async function copyKey() {
    await navigator.clipboard.writeText(revealedKey);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1_500);
  }

  return (
    <>
      <PageHeader eyebrow="Credentials" title="API key management" description="Issue scoped gateway credentials, review usage, and revoke access without downtime." actions={<><span className={`data-mode ${loaded ? "live" : "demo"}`}><i /> {loaded ? "Live credentials" : "Credentials unavailable"}</span><button className="button primary" type="button" disabled={!loaded} onClick={() => { setModalOpen(true); setRevealedKey(""); }}><CirclePlus size={16} /> Create API key</button></>} />
      <section className="key-callout"><div><span className="key-callout-icon"><Shield size={21} /></span><span><strong>Keys are stored as one-way digests</strong><small>Sentinel Edge reveals a secret exactly once. Copy it to your secret manager before closing the dialog.</small></span></div><a href="/dashboard/audit">Review credential events →</a></section>
      {error ? <div className="inline-notice error" role="status" aria-live="polite">{error}</div> : null}
      <section className="panel key-list">
        <div className="panel-heading"><div><h2>Workspace keys</h2><p>{keys.filter((key) => key.status === "active").length} active credentials</p></div></div>
        <div className="table-wrap spacious"><table><thead><tr><th>Name</th><th>Key prefix</th><th>Scopes</th><th>Status</th><th>Last used</th><th>Expires</th><th aria-label="Actions" /></tr></thead><tbody>{keys.map((key) => <tr key={key.id}><td><span className="key-name"><i><KeyRound size={16} /></i><span><strong>{key.name}</strong><small>Created {new Date(key.created_at).toLocaleDateString()}</small></span></span></td><td><code className="key-prefix">{key.key_prefix}••••••••</code></td><td><div className="scope-list">{(JSON.parse(key.scopes_json) as string[]).map((scope) => <span key={scope}>{scope}</span>)}</div></td><td><StatusBadge value={key.status} /></td><td>{key.last_used_at ? new Date(key.last_used_at).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "Never"}</td><td>{key.expires_at ? new Date(key.expires_at).toLocaleDateString() : "Never"}</td><td><button className="icon-button danger-hover" type="button" onClick={() => revoke(key.id)} disabled={key.status !== "active"} aria-label={`Revoke ${key.name}`}><Trash2 size={16} /></button></td></tr>)}</tbody></table></div>
        {keys.length === 0 ? <div className="table-empty"><KeyRound size={22} /><strong>No API keys issued</strong><span>Create a scoped key for your first gateway client.</span></div> : null}
      </section>
      {modalOpen ? <div className="modal-backdrop"><section className="modal key-modal" role="dialog" aria-modal="true" aria-labelledby="key-dialog-title"><header><div><span className="eyebrow">Workspace credential</span><h2 id="key-dialog-title">{revealedKey ? "Save your API key" : "Create an API key"}</h2></div><button className="icon-button" type="button" onClick={() => setModalOpen(false)} aria-label="Close"><X size={18} /></button></header>{revealedKey ? <div className="revealed-key"><p>This value won’t be shown again. Store it in a secret manager, never in source control.</p><div><code>{revealedKey}</code><button className="button secondary" type="button" onClick={copyKey}>{copied ? <Check size={15} /> : <Copy size={15} />} {copied ? "Copied" : "Copy"}</button></div><button className="button primary full" type="button" onClick={() => setModalOpen(false)}>I’ve stored this key</button></div> : <form onSubmit={create}><label>Key name<input name="name" required minLength={2} placeholder="Production inference" /></label><label>Scope<select name="scope" defaultValue="gateway:invoke"><option value="gateway:invoke">Gateway invoke</option></select></label><div className="form-hint"><Shield size={16} /><span>Start with the narrowest scope. Create separate keys for each environment and workload.</span></div><footer><button className="button ghost" type="button" onClick={() => setModalOpen(false)}>Cancel</button><button className="button primary" type="submit">Create key</button></footer></form>}</section></div> : null}
    </>
  );
}
