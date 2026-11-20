# AgentVerify (private pilot export)

AgentVerify is an early, free service that performs **deterministic calculation checks** and returns **signed Ed25519 receipts** for the results. It can be used as a local stdio MCP server or, opt-in, as a remote MCP endpoint alongside a small FastAPI HTTP API.

## Quickstart

```
pip install -r requirements.txt
python -B pilot_v340.py
```

The pilot script runs its own checks and prints a `pilot_status`; `PASS` is the expected result.

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
