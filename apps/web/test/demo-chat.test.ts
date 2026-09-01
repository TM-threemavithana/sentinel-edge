import { describe, expect, it } from "vitest";
import { buildDemoGatewayUrl, isSameOriginRequest, validateDemoChatPayload } from "../lib/demo-chat";

describe("protected demo chat", () => {
  it("accepts and trims a valid user message", () => {
    expect(validateDemoChatPayload({ message: "  Hello Sentinel  " })).toEqual({ message: "Hello Sentinel" });
  });

  it("rejects empty and oversized messages", () => {
    expect(validateDemoChatPayload({ message: "   " })).toBeNull();
    expect(validateDemoChatPayload({ message: "x".repeat(2_001) })).toBeNull();
  });

  it("requires the browser request to come from the console origin", () => {
    expect(isSameOriginRequest("https://console.example/api/demo/chat", "https://console.example")).toBe(true);
    expect(isSameOriginRequest("https://console.example/api/demo/chat", "https://attacker.example")).toBe(false);
    expect(isSameOriginRequest("https://console.example/api/demo/chat", null)).toBe(false);
  });

  it("builds only a canonical gateway destination", () => {
    expect(buildDemoGatewayUrl("https://gateway.example", "ups_demo").toString()).toBe(
      "https://gateway.example/v1/gateway/ups_demo/chat/completions",
    );
    expect(() => buildDemoGatewayUrl("https://gateway.example/unsafe", "ups_demo")).toThrow("invalid_demo_gateway_origin");
    expect(() => buildDemoGatewayUrl("https://gateway.example", "../unsafe")).toThrow("invalid_demo_upstream_id");
  });
});
