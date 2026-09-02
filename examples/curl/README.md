# curl example

Set the three environment variables described in the parent examples README,
then run:

```bash
curl --fail-with-body \
  "$SENTINEL_GATEWAY_URL/v1/gateway/$SENTINEL_UPSTREAM_ID/chat/completions" \
  -H "content-type: application/json" \
  -H "x-sentinel-key: $SENTINEL_API_KEY" \
  --data '{"model":"openai/gpt-oss-20b","messages":[{"role":"user","content":"Explain API security in one sentence."}],"max_tokens":80}'
```

Never put `SENTINEL_API_KEY` in browser JavaScript, a mobile app, a screenshot,
or source control. Use it only from a trusted backend or serverless function.
