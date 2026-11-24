# Publishing AgentVerify as an Apify Actor

The Actor lives in `.actor/` (definition, input schema, Dockerfile, store README) and `apify_actor/` (entry point). It reuses `app/` and `agentverify_client/` unchanged. The existing Render deployment (`Dockerfile`, `render.yaml`) is untouched.

## Pay-per-event events

Apify defines events and prices in **Console** (Actor > Publication > Monetization > Pay per event), not in a file. The code charges these two names. They must match exactly.

| Event name | Charged when | Proposed price (owner decides) |
|---|---|---|
| `verification` | each check that returns passed or failed | $0.003 |
| `signed-receipt` | each signed receipt, on top of `verification` | $0.005 |

- Error rows (malformed or rejected requests) are never charged.
- `apify-actor-start` is a synthetic event Apify charges itself. Do not charge it in code.
- Remove the default `apify-default-dataset-item` event in Console, or each row is billed twice.
- Apify keeps 20% of event revenue and deducts platform compute costs; you receive the rest. Prices above are a starting point, not a forecast.

## Local checks

```
python -B tests_apify_actor.py      # wrapper logic and packaging checks (needs fastapi, pydantic, cryptography)
apify run --input-file test-input.json   # needs the Apify CLI and `pip install -r requirements-actor.txt`
```

Not yet done: a real `apify run`, a Docker build, and a run on the platform (they need the Apify CLI, network access and an Apify account).

## Signing key

Signing is off unless the user supplies their own key. Generate one with:

```
python -c "import os,base64;print(base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('='))"
```
