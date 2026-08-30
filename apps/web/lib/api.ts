export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code: string,
  ) {
    super(message);
  }
}

const GATEWAY_ORIGIN = typeof process !== 'undefined' && process.env.NEXT_PUBLIC_GATEWAY_ORIGIN
  ? process.env.NEXT_PUBLIC_GATEWAY_ORIGIN
  : "https://sentinel-edge-gateway.tharukamaduwantha62.workers.dev";

export async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const isDev = typeof process !== 'undefined' && process.env.NODE_ENV === "development";
  const origin = isDev ? (process.env.NEXT_PUBLIC_GATEWAY_ORIGIN || "http://127.0.0.1:8787") : GATEWAY_ORIGIN;
  const response = await fetch(`${origin}${path}`, {
    ...init,
    headers: {
      "content-type": "application/json",
      ...init?.headers,
    },
    credentials: "include",
    cache: "no-store",
  });
  const payload = (await response.json().catch(() => ({}))) as {
    error?: { code?: string; message?: string };
  } & T;
  if (!response.ok) {
    throw new ApiError(
      payload.error?.message ?? "The gateway returned an unexpected response",
      response.status,
      payload.error?.code ?? "request_failed",
    );
  }
  return payload;
}
