import { describe, expect, it, vi } from "vitest";
import worker from "../src/index";
import { dispatchAnalysis, processAnalysis } from "../src/analysis";
import type { AnalysisMessage } from "../src/types";

const validMessage: AnalysisMessage = {
  requestEventId: "11111111-1111-4111-8111-111111111111",
  requestId: "22222222-2222-4222-8222-222222222222",
  workspaceId: "ws_test",
  redactedBody: "{}",
  path: "/v1/test",
  method: "POST",
  deterministicSignals: [],
};

describe("analysis queue", () => {
  it("enqueues asynchronous analysis outside free-tier mode", async () => {
    const send = vi.fn().mockResolvedValue(undefined);
    await dispatchAnalysis(validMessage, {
      FREE_TIER_MODE: "false",
      AI_MODE: "async",
      ANALYSIS_QUEUE: { send },
    } as any);
    expect(send).toHaveBeenCalledWith(validMessage);
  });

  it("acknowledges invalid poison messages without retrying", async () => {
    const ack = vi.fn();
    const retry = vi.fn();
    await worker.queue({
      messages: [{ id: "message_invalid", body: { invalid: true }, ack, retry }],
    } as any, {} as any);
    expect(ack).toHaveBeenCalledOnce();
    expect(retry).not.toHaveBeenCalled();
  });

  it("retries valid messages when analysis fails", async () => {
    const ack = vi.fn();
    const retry = vi.fn();
    await worker.queue({
      messages: [{ id: "message_retry", body: validMessage, ack, retry }],
    } as any, {
      FREE_TIER_MODE: "false",
      AI_MODEL: "test-model",
      AI: { run: vi.fn().mockRejectedValue(new Error("model unavailable")) },
    } as any);
    expect(retry).toHaveBeenCalledOnce();
    expect(ack).not.toHaveBeenCalled();
  });

  it("uses idempotent artifact metadata writes before upserting the analysis result", async () => {
    const statements: string[] = [];
    const database = {
      prepare: vi.fn((sql: string) => {
        statements.push(sql);
        return { bind: vi.fn(() => ({ run: vi.fn().mockResolvedValue({ success: true }) })) };
      }),
    };
    const bucket = { put: vi.fn().mockResolvedValue(undefined) };
    const env = {
      FREE_TIER_MODE: "false",
      AI_MODEL: "test-model",
      DB: database,
      ARTIFACTS: bucket,
    } as any;
    const classification = {
      category: "unknown" as const,
      confidence: 0,
      explanation: "No threat detected",
      recommendedAction: "allow" as const,
    };

    await processAnalysis(validMessage, env, classification);
    await processAnalysis(validMessage, env, classification);

    expect(bucket.put).toHaveBeenCalledTimes(2);
    expect(statements.filter((sql) => sql.includes("ON CONFLICT(object_key) DO UPDATE"))).toHaveLength(2);
    expect(statements.filter((sql) => sql.includes("ON CONFLICT(request_event_id) DO UPDATE"))).toHaveLength(2);
  });
});
