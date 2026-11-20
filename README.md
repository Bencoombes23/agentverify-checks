# AgentVerify (private pilot export)

AgentVerify is an early, free service that performs **deterministic calculation checks** and returns **signed Ed25519 receipts** for the results. It can be used as a local stdio MCP server or, opt-in, as a remote MCP endpoint alongside a small FastAPI HTTP API.

## Quickstart

```
pip install -r requirements.txt
python -B pilot_v340.py
```

The pilot script runs its own checks and prints a `pilot_status`; `PASS` is the expected result.

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
- **Receipts** (`/verify/signed`) bind the claim and the source: the signed payload holds the claim, the options, the normalisation version/flags and the **SHA-256 of the normalised source text**, and never the source text itself. Anyone holding the same text can normalise it with the published rules, hash it, and compare. Changing the claim or the hash breaks the signature. `verify_receipt.py` is unchanged and works on these receipts.
- **Limits**: `source_text` 1-65536 characters (and the whole request stays under the 64 KiB body cap); one invalid item rejects a whole batch with 422, as before.

**What this does and does not prove.** A pass means *the supplied text contains the claim after normalisation*. It does not prove the claim is true, that the text is the real or current source, or that it was not edited before you sent it. There is no semantic matching: a paraphrase fails. Tests: `python -B tests_claimsource.py`.

## Honest limits

- Early software. Free. No SLA and no support commitment.
- Single worker only; the rate limit is in-process and is not shared between processes or hosts.
- The HTTP 402 response (`/payments/preview`, opt-in) is an illustrative preview only. No payments exist and nothing is charged or processed.
- No production hosting claims are made. Do not treat this as a hardened, hosted service.
- Receipts are only as trustworthy as the signing key you configure. Protect that key; anyone holding it can issue valid receipts.

## x402 (experimental, testnet-only)

Optional pay-per-call support under the [x402](https://x402.org) standard, so a caller without an API key can pay a small per-call price instead. It is **OFF by default**: unless `AGENTVERIFY_X402_ENABLED=1`, nothing changes and the x402 package is not even imported. API keys keep working and bypass payment.

- It has been built and tested against a fake in-process facilitator only. **No payment has ever been tested with real funds**, and no wallet key is involved or needed (the service only holds a public receiving address).
- x402 payment volumes are small today; this is an option for the owner, not a revenue claim.
- Mainnet is refused unless two extra flags are set. Taking real payments needs owner decisions that have not been made (receiving address, production facilitator, price, hosting).

Details, configuration and the owner checklist: [`X402.md`](X402.md). Tests: `python -B tests_x402.py`.

## License

MIT, see `LICENSE`.
