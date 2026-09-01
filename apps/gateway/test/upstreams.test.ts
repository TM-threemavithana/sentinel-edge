import { describe, expect, it } from "vitest";
import { isDuplicateUpstreamNameError } from "../src/routes/upstreams";

describe("upstream registration", () => {
  it("recognizes the workspace-scoped duplicate-name constraint", () => {
    expect(isDuplicateUpstreamNameError(new Error(
      "D1_ERROR: UNIQUE constraint failed: upstreams.workspace_id, upstreams.name: SQLITE_CONSTRAINT",
    ))).toBe(true);
  });

  it("does not classify unrelated database failures as duplicate names", () => {
    expect(isDuplicateUpstreamNameError(new Error("D1_ERROR: database unavailable"))).toBe(false);
  });
});
