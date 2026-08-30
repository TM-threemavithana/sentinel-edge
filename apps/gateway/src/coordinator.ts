import type { Env } from "./env";

interface RateLimitRequest {
  key: string;
  limit: number;
  windowSeconds: number;
}

interface CounterState {
  requests: number;
  blocked: number;
  bytes: number;
}

export class EdgeCoordinator {
  state: DurableObjectState;
  env: Env;

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request: Request): Promise<Response> {
    try {
      const url = new URL(request.url);
      if (request.method === "POST" && url.pathname === "/rate-limit") return await this.rateLimit(request);
      if (request.method === "POST" && url.pathname === "/counter/increment") return await this.increment(request);
      if (request.method === "POST" && url.pathname === "/presence/touch") return await this.touchPresence(request);
      if (request.method === "GET" && url.pathname === "/snapshot") return await this.snapshot();
      return Response.json({ error: "not_found" }, { status: 404 });
    } catch (e: any) {
      return Response.json({ error: "do_error", message: e.message, stack: e.stack }, { status: 500 });
    }
  }

  private async rateLimit(request: Request): Promise<Response> {
    const input = (await request.json()) as RateLimitRequest;
    const windowMs = Math.max(1, input.windowSeconds) * 1_000;
    const windowStart = Math.floor(Date.now() / windowMs) * windowMs;
    const storageKey = `rate:${input.key}:${windowStart}`;
    const current = (await this.state.storage.get<number>(storageKey)) ?? 0;
    const next = current + 1;
    await this.state.storage.put(storageKey, next);
    await this.state.storage.setAlarm(windowStart + windowMs * 2);
    return Response.json({
      allowed: next <= input.limit,
      remaining: Math.max(0, input.limit - next),
      resetAt: new Date(windowStart + windowMs).toISOString(),
    });
  }

  private async increment(request: Request): Promise<Response> {
    const input = (await request.json()) as { decision: string; bytes?: number };
    const live = (await this.state.storage.get<CounterState>("live")) ?? { requests: 0, blocked: 0, bytes: 0 };
    live.requests++;
    if (input.decision === "blocked" || input.decision === "rate_limited") live.blocked++;
    live.bytes += input.bytes ?? 0;
    await this.state.storage.put("live", live);
    return Response.json({ status: "ok" });
  }

  private async touchPresence(request: Request): Promise<Response> {
    const input = (await request.json()) as { userId: string };
    const expiresAt = Date.now() + 5 * 60 * 1_000;
    await this.state.storage.put(`presence:${input.userId}`, expiresAt);
    await this.state.storage.setAlarm(expiresAt + 60 * 1_000);
    return Response.json({ status: "ok" });
  }

  private async snapshot(): Promise<Response> {
    const live = (await this.state.storage.get<CounterState>("live")) ?? { requests: 0, blocked: 0, bytes: 0 };
    const presence = await this.state.storage.list<number>({ prefix: "presence:" });
    let activeUsers = 0;
    const now = Date.now();
    for (const [_, expiresAt] of presence.entries()) {
      if (expiresAt > now) activeUsers++;
    }
    return Response.json({ live, activeUsers });
  }

  async alarm(): Promise<void> {
    const now = Date.now();
    const presence = await this.state.storage.list<number>({ prefix: "presence:" });
    for (const [key, expiresAt] of presence.entries()) {
      if (now >= expiresAt) {
        await this.state.storage.delete(key);
      }
    }
    const rates = await this.state.storage.list<number>({ prefix: "rate:" });
    for (const [key] of rates.entries()) {
      const parts = key.split(":");
      const windowStart = Number.parseInt(parts[2] ?? "", 10);
      if (Number.isFinite(windowStart) && now >= windowStart + 10 * 60 * 1_000) {
        await this.state.storage.delete(key);
      }
    }
  }
}
