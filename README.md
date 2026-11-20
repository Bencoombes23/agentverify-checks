# AgentVerify (early pilot)

Try it now: a free, AI-run live demo with a shared public key is described in DEMO.md (https://agentverify-checks.onrender.com), and the remote MCP endpoint is https://agentverify-checks.onrender.com/mcp.

AgentVerify is an early, free service that performs **deterministic calculation checks** and returns **signed Ed25519 receipts** for the results. It can be used as a local stdio MCP server or, opt-in, as a remote MCP endpoint alongside a small FastAPI HTTP API.

**Status:** early software, free, no SLA and no support commitment. The supported way to use it is to install and run it yourself. The operator also runs a free AI-run demo instance (see DEMO.md) that sleeps when idle, may be offline or slow, and needs an API key; its remote MCP endpoint is switched on and has been tested on loopback and with an outside connection, not under load. It is not production qualified, makes no high-availability claims, has had no security certification or audit, and makes no payment-revenue claims.
## Quickstart

From a clean clone (tested only on Python 3.14 on Windows; other versions and platforms are untested):

```
python -m venv .venv
# Windows:  .venv\Scripts\activate      Linux/macOS:  source .venv/bin/activate
pip install -r requirements.txt
python -B pilot_v340.py
```

The pilot script starts a local server on `127.0.0.1` with throw-away keys, runs its own checks and prints a `pilot_status`; `PASS` is the expected result. Tests: `python -B tests_av013.py`, `python -B tests_x402.py`, `python -B tests_claimsource.py`.

## Verifying a receipt

Signed receipts (`/verify/signed`) contain `payload`, `algorithm` (`Ed25519`), `public_key` and `signature`. Check one offline with the bundled client, using an issuer public key you obtained from a source you trust (not the key inside the receipt):

```python
from agentverify_client import verify_receipt
ok = verify_receipt(receipt, trusted_public_key)   # True only if signed by that key and unmodified
```

`IssuerTrustStore` in the same package lets you pin several issuer keys and mark them active, retired or revoked. A valid signature proves integrity and issuer identity only, not that a claim is true.

A sample receipt is in [`examples/sample_receipt.json`](examples/sample_receipt.json): `rule_version` `agentverify-0.8.0`, produced by the current code through the remote MCP tool `verify_and_sign` on 2026-11-20 with a **throw-away signing key** (discarded; the embedded public key belongs to no real issuer). It only shows the format; `tests_av013.py` checks that it still verifies against its own embedded key, which proves nothing about any real issuer.

## MCP

- **Local stdio (the default):** `python -m app.mcp_server`. Tools: `verify_calculation`, `verify_batch`, `verify_and_sign`, `check_signed_receipt`, `get_public_key`.
- **Remote (opt-in, off by default):** set `AGENTVERIFY_REMOTE_MCP=1` together with `AGENTVERIFY_PUBLIC_MODE=1`; the endpoint is `/mcp` (Streamable HTTP, stateless) and needs the same `X-API-Key` header as the HTTP API. Hosts other than loopback must be listed in `AGENTVERIFY_MCP_ALLOWED_HOSTS` (exact host names, no wildcards); other `Host` and `Origin` values are rejected. It was verified locally on loopback only (AV-027): tool listing, a signed arithmetic check and a signed claim-vs-source check over the MCP client library, receipts verified with `agentverify_client`, and a wrong `Host`, a bad `Origin` and a missing or wrong key were all rejected. It has not been tested on a public host, and the free demo does not enable it.

## Claim-vs-source checks (AV-018)

Besides arithmetic, three deterministic categories check whether **text you supply** contains what an agent claims it says. Use them on the same routes (`/verify`, `/verify/batch`, `/verify/signed`) and the same MCP tools; they can be mixed with arithmetic items in one batch. No network access: the service never fetches anything (see [`DESIGN_URL_MODE.md`](DESIGN_URL_MODE.md) for why, and how a fetcher might be added safely).

| `calculation_type` | Claim field | Other fields | Passes when |
|---|---|---|---|
| `quote_in_text` | `claim_text` (3-2000 chars) | `source_text`, optional `case_insensitive` | the normalised quote is an exact substring of the normalised source |
| `number_in_text` | `claimed_result` | `source_text`, optional `tolerance` (default **0**), `unit`, `allow_scaling` | a standalone number in the source equals the claim within tolerance |
| `date_in_text` | `claim_text` (ISO `YYYY-MM-DD`) | `source_text`, optional `date_format` (`DMY`, `MDY`, `YMD`) | the same calendar date appears in ISO, `D Month YYYY` or `Month D, YYYY` form (or in the stated numeric format) |

```
{"calculation_type":"number_in_text","claimed_result":"3200000","unit":"$","allow_scaling":true,"source_text":"Seed funding was $3.2m in 2025."}
-> {"status":"passed", ... "evidence":{"source_sha256":"e38ffc65...","found":true,"match_offset":18, ...}}
```

- **Normalisation** (`av-text-norm-1`): Unicode NFC; curly quotes mapped to `'`/`"`; all dashes and the minus sign mapped to `-`; `…` to `...`; soft hyphen, zero-width space, word joiner and BOM removed; every run of Unicode whitespace collapsed to one space and trimmed; optional casefold for quotes only. Nothing else (no stemming, no NFKC, no synonyms).
- **Numbers** are exact `Decimal`s, never floats. `12.50` equals `12.5` (numeric equality). `1234` never matches inside `12345` or `21234`. Thousands separators (`1,234.5`) are understood; `1,23` and `1.2.3` are not numbers. A number directly followed by `k`/`m`/`bn`/`b` (or followed by a space and `thousand`/`million`/`billion`/`bn`/`mn`) is a *scaled* number: it matches only with `allow_scaling: true` (then `3.2m` is 3200000, and no longer matches 3.2). A supplied `unit` (`$ £ € ¥ %` or up to 8 letters) must sit next to the number; without `unit`, the unit is not checked.
- **Dates**: ambiguous numeric forms like `01/02/2026` are never matched unless you state `date_format`. Impossible dates in the text (`31 February 2026`) never match.
- **Receipts** (`/verify/signed`) bind the claim and the source: the signed payload holds the claim, the options, the normalisation version/flags and the **SHA-256 of the normalised source text**, and never the source text itself. Anyone holding the same text can normalise it with the published rules, hash it, and compare. Changing the claim or the hash breaks the signature. The `agentverify_client` verifier (see above) works on these receipts.
- **Limits**: `source_text` 1-65536 characters (and the whole request stays under the 64 KiB body cap); one invalid item rejects a whole batch with 422, as before.

**What this does and does not prove.** A pass means *the supplied text contains the claim after normalisation*. It does not prove the claim is true, that the text is the real or current source, or that it was not edited before you sent it. There is no semantic matching: a paraphrase fails. Tests: `python -B tests_claimsource.py`.

## Honest limits

- Early software. Free. No SLA and no support commitment.
- Single worker only; the rate limit is in-process and is not shared between processes or hosts.
- The HTTP 402 response (`/payments/preview`, opt-in) is an illustrative preview only. No payments exist and nothing is charged or processed.
- No production hosting claims are made. Do not treat this as a hardened, hosted service.
- Receipts are only as trustworthy as the signing key you configure. Protect that key; anyone holding it can issue valid receipts.

## Known limits

- **F03, magnitude rule (Medium):** inputs and claims must have a magnitude between roughly 1E-18 and 1E+18 (at most 30 digits). Some correct but very large or very small results (e.g. 1E+17 x 1E+17) are rejected with HTTP 422. These are false rejections, not wrong answers. Not changed.
- **F04, idempotency key can stay stuck (Medium, suspected):** read from the code, not executed (needs PostgreSQL). After a quota or transient failure an `Idempotency-Key` may stay blocked until retention ends; use a new key.
- **F05, durable credentials are Windows-only (Medium):** the durable credential store (and therefore idempotency) works only on Windows and fails closed elsewhere. The default static-key mode is unaffected.
- Single worker only; the rate limit and the replay store are in-process. PostgreSQL paths and cloud recovery were not verified; remote MCP was verified on loopback only (see MCP above). Tested on one Windows machine only.
- Never run a reverse proxy in front of the local-dev bypass, and never enable that bypass on a shared host.

## x402 (experimental, testnet-only)

Optional pay-per-call support under the [x402](https://x402.org) standard, so a caller without an API key can pay a small per-call price instead. It is **OFF by default**: unless `AGENTVERIFY_X402_ENABLED=1`, nothing changes and the x402 package is not even imported. API keys keep working and bypass payment.

- It has been built and tested against a fake in-process facilitator only. **No payment has ever been tested with real funds**, and no wallet key is involved or needed (the service only holds a public receiving address).
- x402 payment volumes are small today; this is an option for the owner, not a revenue claim.
- Mainnet is refused unless two extra flags are set. Taking real payments needs owner decisions that have not been made (receiving address, production facilitator, price, hosting).

Details, configuration and the owner checklist: [`X402.md`](X402.md). Tests: `python -B tests_x402.py`.

## License

MIT, see `LICENSE`.
