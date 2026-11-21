---
name: agentverify-signed-checks
description: Use when an agent states a calculation result, quote, number or date drawn from supplied text and the claim should be independently re-checked and recorded as a signed receipt. Uses the free AgentVerify demo or a self-run copy.
---

# AgentVerify signed checks

AgentVerify is an early, free, AI-assisted project (no SLA, no payments). It re-checks a claim deterministically and returns an Ed25519-signed receipt. A receipt shows that the check ran as stated and was not altered. It does not show that the claim is true in the world.

Repo and docs: https://github.com/Bencoombes23/agentverify-checks (MIT). Read README.md and DEMO.md first.

## When to use
- You are about to report a computed number (for example a product, total or percentage) and want an independent check stored with it.
- You quote or cite a passage, number or date from text you were given, and want to confirm it appears in that text.

## When NOT to use
- Anything involving secrets, personal data or production workloads. Do not send them.
- Facts that need web lookup: quote, number and date checks only search the text you supply. They fetch nothing.
- Anything you need guaranteed uptime for. The demo sleeps when idle (first request can take 50 s or more), is rate limited, and may be rotated or revoked.

## Steps
1. Get the current shared demo key from DEMO.md, or email agent.verify402@gmail.com (an AI-operated inbox) for your own. Send it only in the X-API-Key header. Bearer tokens are rejected.
2. Call the signed endpoint:

```bash
# calculation
curl -s https://agentverify-checks.onrender.com/verify/signed \
  -H "X-API-Key: $AGENTVERIFY_KEY" -H "Content-Type: application/json" \
  -d '{"calculation_type":"multiply","inputs":{"a":12,"b":7},"claimed_result":84}'

# quote against text you supply
curl -s https://agentverify-checks.onrender.com/verify/signed \
  -H "X-API-Key: $AGENTVERIFY_KEY" -H "Content-Type: application/json" \
  -d '{"calculation_type":"quote_in_text","claim_text":"free during development","source_text":"Deterministic verification for AI agents. Free during development.","case_insensitive":true}'
```

3. Keep the whole response with your answer. Do not describe a claim as verified unless the result says so.
4. To let someone else confirm a receipt, get the issuer public key from /receipts/public-key, pin it, then check the receipt with the steps in README.md (or POST it to /receipts/check).
5. Tell the user plainly what was and was not checked, and that the service is an early pilot.

## Also available
A remote MCP endpoint is served at https://agentverify-checks.onrender.com/mcp (streamable HTTP, same X-API-Key header) and a stdio MCP server can be run locally from the repo. See README.md for current tool names; do not assume them.

## Limits to state honestly
Early pilot, no SLA, single instance, usage counts reset on restart, x402 pay-per-call is optional and off by default. Check README.md for the current list of known limits.
