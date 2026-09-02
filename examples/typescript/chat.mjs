const gatewayUrl = process.env.SENTINEL_GATEWAY_URL;
const upstreamId = process.env.SENTINEL_UPSTREAM_ID;
const apiKey = process.env.SENTINEL_API_KEY;

if (!gatewayUrl || !upstreamId || !apiKey) {
  throw new Error("Set SENTINEL_GATEWAY_URL, SENTINEL_UPSTREAM_ID, and SENTINEL_API_KEY");
}

const response = await fetch(`${gatewayUrl}/v1/gateway/${encodeURIComponent(upstreamId)}/chat/completions`, {
  method: "POST",
  headers: {
    "content-type": "application/json",
    "x-sentinel-key": apiKey,
  },
  body: JSON.stringify({
    model: "openai/gpt-oss-20b",
    messages: [{ role: "user", content: "Explain API security in one sentence." }],
    max_tokens: 80,
  }),
});

const payload = await response.json();
if (!response.ok) {
  throw new Error(`Sentinel Edge rejected the request (${response.status}): ${JSON.stringify(payload)}`);
}

console.log(payload.choices?.[0]?.message?.content ?? payload);
console.log("Sentinel request ID:", response.headers.get("x-sentinel-request-id") ?? "not returned");
