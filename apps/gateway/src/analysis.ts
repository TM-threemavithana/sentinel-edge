import { storeAnalysisReport } from "./artifacts";
import { classifyThreat, type AiClassification } from "./ai";
import type { Env } from "./env";
import type { AnalysisMessage } from "./types";

export async function processAnalysis(
  input: AnalysisMessage,
  env: Env,
  precomputedClassification?: AiClassification,
): Promise<void> {
  const classification = precomputedClassification ?? await classifyThreat(env, {
    method: input.method,
    path: input.path,
    redactedBody: input.redactedBody,
    deterministicSignals: input.deterministicSignals,
  });
  const report = {
    requestId: input.requestId,
    generatedAt: new Date().toISOString(),
    model: env.AI_MODEL,
    classification,
    deterministicSignals: input.deterministicSignals,
    handling: "Request content was redacted and truncated before analysis.",
  };
  const artifactKey = await storeAnalysisReport(env, {
    workspaceId: input.workspaceId,
    requestEventId: input.requestEventId,
    requestId: input.requestId,
    report,
  });
  await env.DB.prepare(
    `INSERT INTO analysis_results (id, request_event_id, model, category, confidence, explanation, recommended_action, artifact_key)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(request_event_id) DO UPDATE SET
       model = excluded.model, category = excluded.category, confidence = excluded.confidence,
       explanation = excluded.explanation, recommended_action = excluded.recommended_action, artifact_key = excluded.artifact_key`,
  ).bind(
    crypto.randomUUID(),
    input.requestEventId,
    env.AI_MODEL,
    classification.category,
    classification.confidence,
    classification.explanation,
    classification.recommendedAction,
    artifactKey,
  ).run();
}

export async function dispatchAnalysis(
  input: AnalysisMessage,
  env: Env,
  precomputedClassification?: AiClassification,
): Promise<void> {
  if (env.FREE_TIER_MODE === "true" || env.AI_MODE === "inline" || precomputedClassification) {
    await processAnalysis(input, env, precomputedClassification);
    return;
  }
  if (!env.ANALYSIS_QUEUE) throw new Error("ANALYSIS_QUEUE is required for asynchronous AI mode");
  await env.ANALYSIS_QUEUE.send(input);
}
