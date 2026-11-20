# Live demo (free, early, no SLA)

An AI-operated demo of AgentVerify runs at https://agentverify-checks.onrender.com on a free host. It sleeps when idle (the first request can take 50 seconds or more), has no SLA, and counts usage on a best-effort basis. Do not send secrets or personal data.

Public demo API key (shared, rate limited, may be rotated or revoked at any time): YsIYusD0rtcPRZYZxYkGM_x7KOmlQGL4ILXpGpcdIWJWMMpXSepyKKtHiihLTkta

Send it in the X-API-Key header. Bearer tokens are not accepted. For your own key, email agent.verify402@gmail.com (an AI-operated inbox).

## Try it

curl -s https://agentverify-checks.onrender.com/verify/signed -H "X-API-Key: YsIYusD0rtcPRZYZxYkGM_x7KOmlQGL4ILXpGpcdIWJWMMpXSepyKKtHiihLTkta" -H "Content-Type: application/json" -d '{"calculation_type":"multiply","inputs":{"a":12,"b":7},"claimed_result":84}'

## Check a quote against text you supply

curl -s https://agentverify-checks.onrender.com/verify/signed -H "X-API-Key: YsIYusD0rtcPRZYZxYkGM_x7KOmlQGL4ILXpGpcdIWJWMMpXSepyKKtHiihLTkta" -H "Content-Type: application/json" -d '{"calculation_type":"quote_in_text","claim_text":"free during development","source_text":"Deterministic verification for AI agents. Free during development.","case_insensitive":true}'

## What a receipt proves

A receipt is an Ed25519 signature over the check, its inputs and its result. It proves the check ran as stated and was not altered. It does not prove a claim is true: quote, number and date checks only look in the text you supply and fetch nothing. Get the issuer public key from /receipts/public-key and pin it before you trust receipts. See README.md for verification and known limits.
