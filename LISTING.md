# AgentVerify: listing material

Early pilot software. Free, MIT licensed, no SLA, no support commitment. Contact: agent.verify402@gmail.com

## Description

AgentVerify is an MCP server that lets an AI agent check its own claims deterministically instead of trusting itself. It re-computes arithmetic claims (add, subtract, multiply, divide, percentage and similar) with exact decimals and compares them with the claimed result. It also checks whether text you supply contains a claimed quote, number or date. Every check can return an Ed25519-signed receipt that can be verified offline with the bundled `agentverify_client` against an issuer public key you trust. A passing check proves that the arithmetic is right, or that the supplied text contains the claim. It does not prove that a claim is true or that the supplied text is a genuine source.

## Tools

- `verify_calculation`: check one claimed numerical result, or one quote, number or date claim against text you supply.
- `verify_batch`: check up to 50 such claims in one call.
- `verify_and_sign`: run a check and return an Ed25519-signed receipt.
- `check_signed_receipt`: check that a receipt carries an intact signature from this server's issuer key.
- `get_public_key`: return this server's public signing key.

## Install (local stdio)

```
git clone <repository URL>
cd <cloned directory>
python -m venv .venv
.venv\Scripts\activate          # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
python -B -m app.mcp_server
```

Signing tools need a signing seed: base64url of 32 random bytes in `AGENTVERIFY_SIGNING_KEY_B64`. Generate one yourself and keep it private, for example `python -c "import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('='))"`. `verify_calculation` and `verify_batch` do not need it.

Client configuration (the usual `mcpServers` shape; adjust the paths):

```json
{
  "mcpServers": {
    "agentverify": {
      "command": "<path to venv python>",
      "args": ["-B", "-m", "app.mcp_server"],
      "cwd": "<path to the cloned directory>",
      "env": { "AGENTVERIFY_SIGNING_KEY_B64": "<your own seed>" }
    }
  }
}
```

## Remote endpoint (only if the operator enables it)

URL pattern: `https://agentverify-checks.onrender.com/mcp` (Streamable HTTP, `X-API-Key` header required).

This endpoint is available only if the operator has enabled it (`AGENTVERIFY_REMOTE_MCP=1`). It is off on the free demo at the time of writing, so do not assume it responds. The demo is on a free host that sleeps when idle, so the first request can be slow.

## Honest limits

- Early software, free, no SLA, no support commitment. Not production qualified; no security audit or certification.
- Remote MCP was tested on loopback only, not on a public host. Local stdio was tested on one Windows machine.
- Single worker; the rate limit is in-process.
- A pass shows the arithmetic is right, or that the supplied text contains the claim after normalisation. It does not show the claim is true, the source is genuine, or that the text was unedited. No semantic matching: a paraphrase fails. The service never fetches URLs.
- Numbers must lie between roughly 1E-18 and 1E+18; some correct results outside that range are rejected.
- Receipts are only as trustworthy as the issuer key you pin. Get the public key from a source you trust, not from the receipt.
- An optional x402 pay-per-call mode exists (testnet only, off by default, never tested with real funds). No payments are accepted.

## Licence

MIT, see `LICENSE`.

## Ready-to-paste registry / awesome-list entry

```
- [AgentVerify](<repository URL>) - Deterministic checks for AI agents: re-computes arithmetic claims and checks that supplied text contains a quoted string, number or date, with optional Ed25519-signed receipts. Python, local stdio MCP (remote HTTP opt-in). Early pilot, free, MIT.
```

## Registry manifest (`server.json`)

Not included. The registry's manifest format is not documented in this repository and its exact current schema is not known with certainty here, so a guessed file could be wrong. Add one after checking the registry's published schema.
