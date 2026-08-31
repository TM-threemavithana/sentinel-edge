import type { AnalysisMessage } from "./types";

export interface Env {
  DB: D1Database;
  POLICY_CACHE: KVNamespace;
  ANALYSIS_QUEUE?: Queue<AnalysisMessage>;
  ARTIFACTS?: R2Bucket;
  EDGE_COORDINATOR: DurableObjectNamespace;
  AI: Ai;
  ENVIRONMENT: string;
  AI_MODEL: string;
  AI_MODE: "async" | "inline";
  SESSION_COOKIE: string;
  SESSION_TTL_SECONDS: string;
  MAX_INSPECTION_BYTES: string;
  SESSION_SECRET: string;
  UPSTREAM_ENCRYPTION_KEY: string;
  ALLOWED_ORIGINS?: string;
  FREE_TIER_MODE?: string;
  ACCESS_REQUIRED?: string;
  ACCESS_TEAM_DOMAIN?: string;
  ACCESS_AUD?: string;
  MFA_REQUIRED?: string;
}
