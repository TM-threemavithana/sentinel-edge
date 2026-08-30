export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code: string,
  ) {
    super(message);
  }
}

function getGatewayOrigin(): string {
  const env = typeof process !== "undefined" ? process.env : ({} as Record<string, string | undefined>);
  const origin = env.NEXT_PUBLIC_GATEWAY_ORIGIN;
  if (!origin) {
    if (env.NODE_ENV === "development") return "http://127.0.0.1:8787";
    throw new Error("NEXT_PUBLIC_GATEWAY_ORIGIN must be set in production");
  }
  return origin;
}

let csrfToken: string | null = null;

export function setCsrfToken(token: string): void {
  csrfToken = token;
}

export async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    ...(init?.headers as Record<string, string> | undefined),
  };
  if (csrfToken && init?.method && !["GET", "HEAD", "OPTIONS"].includes(init.method)) {
    headers["x-csrf-token"] = csrfToken;
  }
  const response = await fetch(`${getGatewayOrigin()}${path}`, {
    ...init,
    headers,
    credentials: "include",
    cache: "no-store",
  });
  const payload = (await response.json().catch(() => ({}))) as {
    error?: { code?: string; message?: string };
    csrfToken?: string;
  } & T;
  if (payload.csrfToken) setCsrfToken(payload.csrfToken);
  if (!response.ok) {
    const err = new ApiError(
      payload.error?.message ?? "The gateway returned an unexpected response",
      response.status,
      payload.error?.code ?? "request_failed",
    );
    if (response.status === 401 && typeof window !== "undefined" && window.location.pathname !== "/login") {
      window.dispatchEvent(new CustomEvent("sentinel:session-expired"));
    }
    throw err;
  }
  return payload;
}
