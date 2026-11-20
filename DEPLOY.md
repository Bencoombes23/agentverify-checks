# Deploying the AgentVerify pilot (Render free tier)

Early pilot software. No SLA, no support commitment, not production qualified. Nothing here has been run on Render yet; the local proof (below) used the same start command and environment variable names without Docker.

## What the app needs

- **ASGI entry:** `app.main:app` (FastAPI). Use the guarded launcher so the start-up checks run.
- **Start command:** `python -B -m app.secure_launch --host 0.0.0.0 --port $PORT` (the Dockerfile runs exactly this, with `PORT` defaulting to 10000). One worker only.
- **Health check:** `GET /health` (no API key needed; `/pricing` is also open). Everything else needs an `X-API-Key` header.
- **Database:** none required. Without PostgreSQL the service uses an in-process rate limit and best-effort SQLite usage counters (`AGENTVERIFY_USAGE_DB`, set to `/tmp`). Durable quotas and `Idempotency-Key` need PostgreSQL **and** the Windows-only credential store (known limit F05), so they are **unavailable on Render/Linux**. Nothing is weakened to make it work: those features are simply off.

## Environment variables (names; values are never in git)

| Name | Purpose | Required | Default / value |
|---|---|---|---|
| `AGENTVERIFY_SIGNING_KEY_B64` | Ed25519 signing seed: base64url of 32 random bytes. **Secret.** | yes | none; startup and `/verify/signed` fail closed without it |
| `AGENTVERIFY_API_KEYS` | Comma-separated API keys, each at least 32 characters. **Secret.** | yes | none; requests get 503 without it |
| `AGENTVERIFY_PUBLIC_MODE` | Enables the public-hosting checks | yes | `1` (set in render.yaml) |
| `AGENTVERIFY_CLOUD_MODE` | Extra cloud start-up validation | yes | `1` (set in render.yaml) |
| `AGENTVERIFY_USAGE_DB` | SQLite usage file path | recommended | `/tmp/agentverify-usage.sqlite3` (the default path is inside the app directory, which is read-only in the image) |
| `AGENTVERIFY_RATE_LIMIT_PER_MINUTE` | Per-key, in-process rate limit (1-100000) | optional | `60` |
| `AGENTVERIFY_MAX_BODY_BYTES` | Request body cap (1024 to 8 MiB) | optional | 64 KiB |
| `AGENTVERIFY_REMOTE_MCP` | `1` mounts remote MCP at `/mcp` (needs public mode) | optional | off. Remote MCP was **not** verified |
| `AGENTVERIFY_MCP_ALLOWED_HOSTS` | Comma-separated public host names allowed for MCP (F06), e.g. `your-service.onrender.com`; no wildcards | only with remote MCP | localhost only |
| `AGENTVERIFY_READINESS_ENABLED` / `AGENTVERIFY_READINESS_KEY` | Optional operator `/ready` (key at least 32 chars, secret) | optional | off |
| `PORT` | Port to bind (host `0.0.0.0`) | set by Render | 10000 in the image |

Leave these **unset** on Render: all `AGENTVERIFY_X402_*` (x402 stays off, no payments), `AGENTVERIFY_DEV_PAYMENT_PREVIEW` (forbidden on public hosts), `AGENTVERIFY_LOCAL_*` and the local-dev bypass (conflicts with hosting; the app refuses to start), `AGENTVERIFY_DURABLE_QUOTAS`, `AGENTVERIFY_IDEMPOTENCY_V390`, `AGENTVERIFY_USAGE_BACKEND=postgres` and `AGENTVERIFY_DATABASE_URL` (they demand a managed PostgreSQL schema; see limits).

Render sets `RENDER=true` itself; the app treats that as hosted and applies the strict public checks.

## Steps for the owner (Render free tier)

1. **Generate the secrets locally** (nothing is written to disk by these commands; copy the output straight into the Render dashboard, never into git, chat or a file in the repo):
   - Signing key: `python -c "import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('='))"`
   - API key: `python -c "import secrets;print(secrets.token_urlsafe(48))"`
   - Keep a private backup of the signing key. If it is lost, the issuer identity changes and old receipts can no longer be tied to the new key.
2. In Render: **New > Blueprint**, connect the GitHub repository, select `render.yaml` (or **New > Web Service**, runtime Docker, plan Free, health check path `/health`).
3. When prompted for the variables marked `sync: false`, paste `AGENTVERIFY_SIGNING_KEY_B64` and `AGENTVERIFY_API_KEYS`. Leave `AGENTVERIFY_MCP_ALLOWED_HOSTS` empty unless you enable remote MCP.
4. Deploy and wait for `GET https://<service>.onrender.com/health` to return `{"status":"healthy",...}`.
5. **Read the public key and issuer fingerprint** (the key endpoint needs an API key):
   `curl -H "X-API-Key: <your key>" https://<service>.onrender.com/receipts/public-key`
   Compare with what you can compute offline from your own seed so you do not rely on the service alone. The fingerprint is `agentverify_client.issuer_fingerprint(public_key)` (SHA-256 of the raw 32-byte key). Publish the public key and fingerprint on a channel you control; callers should pin it with `IssuerTrustStore`.
6. **Verify with a receipt:**
   `curl -X POST https://<service>.onrender.com/verify/signed -H "X-API-Key: <your key>" -H "Content-Type: application/json" -d '{"calculation_type":"arithmetic","claimed_result":"3","inputs":{"a":"1","b":"2"}}'`
   then, in Python, `agentverify_client.verify_receipt(receipt, trusted_public_key)` using the key from step 5 (not the one inside the receipt). It must return `True`, and `False` after you change any field.

## Honest limits

- **Free tier sleeps** after about 15 minutes idle; the first request afterwards is slow (cold start) and may time out for impatient clients.
- **No SLA, no support commitment**, single instance, single worker, no high-availability.
- **State is lost on restart/redeploy:** the in-process rate limit resets, and the SQLite usage counters (in `/tmp`) disappear. Receipts are unaffected: the signing key comes from the environment, so the issuer identity survives restarts. No receipt is stored server-side.
- **No PostgreSQL is configured, so** there are no durable quotas and no idempotency keys. Render's free PostgreSQL **expires** (about 30 days) and would not fix this anyway, because those features also rely on the Windows-only credential store (F05) and on a manually managed schema (`migrations/v400_stage2_postgres.sql`).
- The rate limit is per API key and per process. All users of one shared key share one bucket.
- Dependencies (`x402[evm]` and `mcp`) are installed from `requirements.txt` even though x402 stays off; the image build was not run here (no Docker available) and the Python 3.14 base image tag was not pulled.
- Receipts prove integrity and issuer identity only, not that a claim is true.

## Public demo mode (one page)

Goal: let people try the service without handing out personal keys.

- Every verification route requires an API key, even when public. A "public demo" therefore means **deliberately publishing one demo key** (a separate, throw-away value in `AGENTVERIFY_API_KEYS`, which accepts several comma-separated keys). This is an owner decision.
- Treat the demo key as burnable: anyone can read it, share one rate-limit bucket (60/min by default; lower it with `AGENTVERIFY_RATE_LIMIT_PER_MINUTE`), and abuse it. Rotate by editing the variable and redeploying. Keep your own non-published key in the list for yourself.
- Do not reuse the signing key anywhere else, and never publish it. Receipts from the demo are real signed receipts from the real issuer key; say so, or use a separate demo service with its own key.
- No payments: x402 stays off, `/payments/preview` is disabled, `/pricing` reports free. No personal data is stored; usage counters hold counts only.
- Suggested banner text: "Free early pilot. Deterministic calculation checks with signed receipts. No SLA; may be offline or slow after idle; not for production decisions."
- Request bodies are capped at 64 KiB and numbers outside roughly 1E-18 to 1E+18 are rejected (known limit F03).

## Local proof (no Docker)

The same start command and environment (`PORT`, `RENDER=true`, public and cloud mode, throw-away signing seed and API key in a temp directory) was run on this machine with host `0.0.0.0` and probed over loopback: `/health` returned 200, a request without a key returned 401, `/receipts/public-key` and a signed `/verify/signed` call returned 200, `agentverify_client.verify_receipt` returned `True` (and `False` for a tampered receipt), and no `.agentverify` directory was created.
