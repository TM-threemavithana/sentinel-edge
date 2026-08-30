import { z } from "zod";

export const loginSchema = z.object({
  email: z.email().max(254),
  password: z.string().min(12).max(256),
});

export const apiKeySchema = z.object({
  name: z.string().trim().min(2).max(80),
  expiresAt: z.iso.datetime().nullable().optional(),
  scopes: z.array(z.enum(["gateway:invoke", "analytics:read"])).min(1).max(4),
});

const conditionSchema = z.discriminatedUnion("field", [
  z.object({ field: z.literal("method"), operator: z.enum(["equals", "in"]), value: z.union([z.string(), z.array(z.string())]) }),
  z.object({ field: z.literal("path"), operator: z.enum(["equals", "starts_with", "matches"]), value: z.string().max(256) }),
  z.object({ field: z.literal("header"), operator: z.enum(["equals", "contains", "exists"]), key: z.string().max(80), value: z.string().max(256).optional() }),
  z.object({ field: z.literal("country"), operator: z.enum(["equals", "in"]), value: z.union([z.string(), z.array(z.string())]) }),
  z.object({ field: z.literal("threat"), operator: z.enum(["equals", "in"]), value: z.union([z.string(), z.array(z.string())]) }),
  z.object({ field: z.literal("severity"), operator: z.literal("at_least"), value: z.enum(["low", "medium", "high", "critical"]) }),
  z.object({ field: z.literal("body"), operator: z.enum(["contains", "matches"]), value: z.string().max(256) }),
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

export const policyPatchSchema = policySchema.partial().extend({ id: z.string().min(1) });

export const upstreamSchema = z.object({
  name: z.string().trim().min(2).max(80),
  baseUrl: z.url().refine((value) => {
    const url = new URL(value);
    const host = url.hostname.toLowerCase();
    const isPrivate =
      host === "localhost" ||
      host === "::1" ||
      host.endsWith(".local") ||
      /^127\./u.test(host) ||
      /^10\./u.test(host) ||
      /^192\.168\./u.test(host) ||
      /^169\.254\./u.test(host) ||
      /^172\.(?:1[6-9]|2\d|3[01])\./u.test(host);
    return url.protocol === "https:" && !isPrivate && !url.username && !url.password;
  }, "Upstream must be a public HTTPS origin"),
  authHeaderName: z.string().regex(/^[a-z0-9-]+$/i).default("authorization"),
  authValue: z.string().max(2_048).optional(),
  timeoutMs: z.number().int().min(1_000).max(120_000).default(30_000),
});
