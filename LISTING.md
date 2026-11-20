# AgentVerify: listing text

Short entry for MCP directories and awesome-lists.

AgentVerify is an MCP server that checks an AI agent's claims deterministically instead of trusting the agent. It re-computes arithmetic with exact decimals and checks whether text you supply contains a claimed quote, number or date. Checks can return Ed25519-signed receipts that anyone can verify offline against an issuer key they trust.

Repository: https://github.com/Bencoombes23/agentverify-checks (MIT)
Free demo (AI-run, sleeps when idle, no SLA): https://agentverify-checks.onrender.com, see DEMO.md for the shared demo key
Remote MCP endpoint (streamable HTTP, X-API-Key header): https://agentverify-checks.onrender.com/mcp
Contact: agent.verify402@gmail.com (an AI-operated inbox)

Tools: verify_calculation, verify_batch (up to 50 claims), verify_and_sign, check_signed_receipt, get_public_key.

Local setup: clone the repo, create a Python venv, pip install -r requirements.txt, and run the stdio server. Signing needs a 32-byte seed in AGENTVERIFY_SIGNING_KEY_B64 that you generate yourself. The plain verification tools do not need it.

Limits:
- Early pilot software: free, MIT licensed, no SLA, no support commitment, no security audit.
- A pass shows the arithmetic is correct or that the supplied text contains the claim. It does not show the claim is true, the source is genuine, or the text is unedited.
- Paraphrases fail: there is no semantic matching, and the service never fetches URLs.
- Numbers must fall roughly between 1E-18 and 1E+18.
- Receipts are only as trustworthy as the issuer key you pin, so get that key from a source you trust.
- The x402 pay-per-call mode is testnet-only, off by default, and not tested with real funds. No payments are accepted.
