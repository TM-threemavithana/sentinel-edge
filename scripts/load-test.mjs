import { performance } from "node:perf_hooks";

const target = process.env.LOAD_URL ?? "http://127.0.0.1:8787/health";
const total = Number(process.env.LOAD_REQUESTS ?? 50);
const concurrency = Number(process.env.LOAD_CONCURRENCY ?? 5);
const expectedStatus = Number(process.env.LOAD_EXPECTED_STATUS ?? 200);
const sentinelKey = process.env.SENTINEL_API_KEY;

if (!URL.canParse(target) || total < 1 || total > 5000 || concurrency < 1 || concurrency > 100) {
  throw new Error("Use a valid LOAD_URL, 1-5000 LOAD_REQUESTS, and 1-100 LOAD_CONCURRENCY");
}

const durations = [];
let succeeded = 0;
let failed = 0;
let cursor = 0;

async function worker() {
  while (cursor < total) {
    cursor += 1;
    const started = performance.now();
    try {
      const response = await fetch(target, {
        headers: sentinelKey ? { "x-sentinel-key": sentinelKey } : undefined,
        signal: AbortSignal.timeout(15_000),
      });
      durations.push(performance.now() - started);
      if (response.status === expectedStatus) succeeded += 1;
      else failed += 1;
      await response.body?.cancel();
    } catch {
      durations.push(performance.now() - started);
      failed += 1;
    }
  }
}

const suiteStarted = performance.now();
await Promise.all(Array.from({ length: Math.min(concurrency, total) }, () => worker()));
const elapsedSeconds = (performance.now() - suiteStarted) / 1000;
durations.sort((a, b) => a - b);
const percentile = (value) => durations[Math.min(durations.length - 1, Math.ceil(durations.length * value) - 1)] ?? 0;

console.log(`Target: ${new URL(target).origin}${new URL(target).pathname}`);
console.log(`Requests: ${total}; succeeded: ${succeeded}; failed: ${failed}; concurrency: ${concurrency}`);
console.log(`Throughput: ${(total / elapsedSeconds).toFixed(2)} requests/second`);
console.log(`Latency: p50 ${percentile(0.5).toFixed(1)} ms; p95 ${percentile(0.95).toFixed(1)} ms; max ${percentile(1).toFixed(1)} ms`);

if (failed > 0) process.exitCode = 1;
