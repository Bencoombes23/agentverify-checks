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

## License

MIT, see `LICENSE`.
