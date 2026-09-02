import { z } from "zod";
import { isValidPolicyRegex } from "@sentinel/security-core";
import { isSafeUpstreamUrl } from "./upstream-safety";

const FORBIDDEN_UPSTREAM_AUTH_HEADERS = new Set([
  "connection",
  "content-length",
  "cookie",
  "host",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "x-sentinel-key",
]);

export type JsonBodyResult =
  | { success: true; data: unknown }
  | { success: false; reason: "invalid" | "too_large" };

export async function readJsonBody(request: Request, limit = 64 * 1024): Promise<JsonBodyResult> {
  const declaredLength = request.headers.get("content-length");
  if (declaredLength !== null) {
    const value = Number(declaredLength);
    if (!Number.isSafeInteger(value) || value < 0 || value > limit) {
      return { success: false, reason: "too_large" };
    }
  }
  if (!request.body) return { success: false, reason: "invalid" };

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let received = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    received += value.byteLength;
    if (received > limit) {
      await reader.cancel();
      return { success: false, reason: "too_large" };
    }
    chunks.push(value);
  }

  const bytes = new Uint8Array(received);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return { success: true, data: JSON.parse(new TextDecoder().decode(bytes)) };
  } catch {
    return { success: false, reason: "invalid" };
  }
}

const threatSignalSchema = z.object({
  category: z.enum(["prompt_injection", "sqli", "xss", "ssrf", "path_traversal", "secret_exposure", "oversized_payload", "malicious_file", "unknown"]),
  severity: z.enum(["low", "medium", "high", "critical"]),
  confidence: z.number().min(0).max(1),
  source: z.enum(["deterministic", "workers_ai"]),
  summary: z.string().max(500),
});

export const analysisMessageSchema = z.object({
  requestEventId: z.string().uuid(),
  requestId: z.string().uuid(),
  workspaceId: z.string().min(1).max(128),
  redactedBody: z.string().max(12_000),
  path: z.string().max(2_048),
  method: z.string().min(1).max(16),
  deterministicSignals: z.array(threatSignalSchema).max(32),
});

export const loginSchema = z.object({
  email: z.email().max(254),
  password: z.string().min(12).max(256),
});

export const mfaVerifySchema = z.object({
  challengeToken: z.string().min(32).max(128),
  code: z.string().trim().min(6).max(32),
});

export const mfaConfirmSchema = z.object({
  code: z.string().regex(/^\d{6}$/u),
  newPassword: z.string().min(16).max(256),
});

export const apiKeySchema = z.object({
  name: z.string().trim().min(2).max(80),
  expiresAt: z.iso.datetime().nullable().optional(),
  scopes: z.array(z.enum(["gateway:invoke", "analytics:read"])).min(1).max(4),
});

const conditionSchema = z.discriminatedUnion("field", [
  z.object({ field: z.literal("method"), operator: z.enum(["equals", "in"]), value: z.union([z.string(), z.array(z.string())]) }),
  z.object({ field: z.literal("path"), operator: z.enum(["equals", "starts_with", "matches"]), value: z.string().max(256).refine(isValidPolicyRegex, "Expression is not supported by the linear-time policy matcher") }),
  z.object({ field: z.literal("header"), operator: z.enum(["equals", "contains", "exists"]), key: z.string().max(80), value: z.string().max(256).optional() }),
  z.object({ field: z.literal("country"), operator: z.enum(["equals", "in"]), value: z.union([z.string(), z.array(z.string())]) }),
  z.object({ field: z.literal("threat"), operator: z.enum(["equals", "in"]), value: z.union([z.string(), z.array(z.string())]) }),
  z.object({ field: z.literal("severity"), operator: z.literal("at_least"), value: z.enum(["low", "medium", "high", "critical"]) }),
  z.object({ field: z.literal("body"), operator: z.enum(["contains", "matches"]), value: z.string().max(256).refine(isValidPolicyRegex, "Expression is not supported by the linear-time policy matcher") }),
]);

export const policySchema = z.object({
  name: z.string().trim().min(3).max(100),
  description: z.string().trim().max(500).default(""),
  priority: z.number().int().min(1).max(100_000),
  action: z.enum(["allow", "block", "challenge", "log"]),
  conditions: z.array(conditionSchema).min(1).max(12),
  rateLimit: z
    .object({
      requests: z.number().int().min(1).max(1_000_000),
      windowSeconds: z.number().int().min(1).max(86_400),
      keyBy: z.enum(["api_key", "ip", "workspace"]),
    })
    .nullable()
    .optional(),
  enabled: z.boolean().default(true),
});

export const policyPatchSchema = z.object({
  name: z.string().trim().min(3).max(100).optional(),
  description: z.string().trim().max(500).optional(),
  priority: z.number().int().min(1).max(100_000).optional(),
  action: z.enum(["allow", "block", "challenge", "log"]).optional(),
  conditions: z.array(conditionSchema).min(1).max(12).optional(),
  rateLimit: z
    .object({
      requests: z.number().int().min(1).max(1_000_000),
      windowSeconds: z.number().int().min(1).max(86_400),
      keyBy: z.enum(["api_key", "ip", "workspace"]),
    })
    .nullable()
    .optional(),
  enabled: z.boolean().optional(),
  id: z.string().min(1),
});

export const upstreamSchema = z.object({
  name: z.string().trim().min(2).max(80),
  baseUrl: z.url().max(2_048).refine(isSafeUpstreamUrl, "Upstream must be a public HTTPS origin"),
  authHeaderName: z.string().regex(/^[a-z0-9-]+$/i).refine(
    (value) => !FORBIDDEN_UPSTREAM_AUTH_HEADERS.has(value.toLowerCase()) && !value.toLowerCase().startsWith("cf-"),
    "This authentication header cannot be forwarded safely",
  ).default("authorization"),
  authValue: z.string().max(2_048).optional(),
  timeoutMs: z.number().int().min(1_000).max(120_000).default(30_000),
});
