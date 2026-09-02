"""Call an OpenAI-compatible provider through Sentinel Edge using only the standard library."""

import json
import os
import http.client
import urllib.parse

gateway_url = os.environ.get("SENTINEL_GATEWAY_URL")
upstream_id = os.environ.get("SENTINEL_UPSTREAM_ID")
api_key = os.environ.get("SENTINEL_API_KEY")

if not all((gateway_url, upstream_id, api_key)):
    raise SystemExit("Set SENTINEL_GATEWAY_URL, SENTINEL_UPSTREAM_ID, and SENTINEL_API_KEY")

parsed_gateway = urllib.parse.urlsplit(gateway_url)
is_local_http = parsed_gateway.scheme == "http" and parsed_gateway.hostname in {"localhost", "127.0.0.1"}
if parsed_gateway.scheme != "https" and not is_local_http:
    raise SystemExit("SENTINEL_GATEWAY_URL must use HTTPS, except for localhost development")
if parsed_gateway.username or parsed_gateway.password or parsed_gateway.query or parsed_gateway.fragment:
    raise SystemExit("SENTINEL_GATEWAY_URL cannot contain credentials, a query, or a fragment")

path = f"{parsed_gateway.path.rstrip('/')}/v1/gateway/{urllib.parse.quote(upstream_id, safe='')}/chat/completions"
body = json.dumps(
    {
        "model": "openai/gpt-oss-20b",
        "messages": [{"role": "user", "content": "Explain API security in one sentence."}],
        "max_tokens": 80,
    }
)

try:
    connection_type = http.client.HTTPSConnection if parsed_gateway.scheme == "https" else http.client.HTTPConnection
    connection = connection_type(parsed_gateway.hostname, parsed_gateway.port, timeout=30)
    connection.request(
        "POST",
        path,
        body=body,
        headers={"content-type": "application/json", "x-sentinel-key": api_key},
    )
    response = connection.getresponse()
    payload = json.loads(response.read())
    if response.status >= 400:
        raise SystemExit(f"Sentinel Edge rejected the request ({response.status}): {payload}")
    print(payload.get("choices", [{}])[0].get("message", {}).get("content", payload))
    print("Sentinel request ID:", response.getheader("x-sentinel-request-id", "not returned"))
finally:
    if "connection" in locals():
        connection.close()
