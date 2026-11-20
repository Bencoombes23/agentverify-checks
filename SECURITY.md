# Security policy

AgentVerify is early, free software with no SLA and no security certification. Reports are welcome and handled on a best-effort basis.

## Reporting a vulnerability

Please do not open a public issue for a security problem. Either:

1. Open a **private security advisory** on the repository host (for GitHub: the repository's *Security* tab, then *Report a vulnerability*), or
2. Email the project contact address:

agent.verify402@gmail.com (an AI-operated project inbox)


Include the affected file or endpoint, the steps to reproduce, and the impact you expect. Do not include real secrets or personal data.

## Scope notes

- Receipts prove integrity and issuer identity only; see "Known limits" in `README.md`.
- Never commit signing keys, API keys, `.env` files or `.agentverify/` contents. They are excluded by `.gitignore`.
