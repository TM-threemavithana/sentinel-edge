export const DEMO_MESSAGE_LIMIT = 2_000;
export const DEMO_BODY_LIMIT = 8 * 1_024;

export type DemoChatPayload = {
  message: string;
};

export function validateDemoChatPayload(value: unknown): DemoChatPayload | null {
  if (!value || typeof value !== "object") return null;
  const message = Reflect.get(value, "message");
  if (typeof message !== "string") return null;
  const trimmed = message.trim();
  if (!trimmed || trimmed.length > DEMO_MESSAGE_LIMIT) return null;
  return { message: trimmed };
}

export function isSameOriginRequest(requestUrl: string, origin: string | null): boolean {
  if (!origin) return false;
  try {
    return new URL(origin).origin === new URL(requestUrl).origin;
  } catch {
    return false;
  }
}

export function buildDemoGatewayUrl(gatewayOrigin: string, upstreamId: string): URL {
  const origin = new URL(gatewayOrigin);
  if (
    origin.protocol !== "https:" &&
    !(origin.protocol === "http:" && ["127.0.0.1", "localhost"].includes(origin.hostname))
  ) {
    throw new Error("invalid_demo_gateway_origin");
  }
  if (origin.pathname !== "/" || origin.search || origin.hash || origin.username || origin.password) {
    throw new Error("invalid_demo_gateway_origin");
  }
  if (!/^[a-zA-Z0-9_-]{1,128}$/u.test(upstreamId)) throw new Error("invalid_demo_upstream_id");
  return new URL(`/v1/gateway/${encodeURIComponent(upstreamId)}/chat/completions`, origin.origin);
}
