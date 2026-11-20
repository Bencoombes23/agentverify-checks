"""AV-013 checks (stdlib only; the export has no pytest).

Run:  <venv python> -B tests_av013.py
Drives the real ASGI app directly (no sockets) so peer/listener/headers are exact.
Usage telemetry is pointed at a temp dir; nothing is written inside the export.
"""
import asyncio
import json
import os
import secrets
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))

KEY = secrets.token_urlsafe(40)
SEED_B64 = "A" * 43  # base64url of 32 zero bytes: synthetic test seed only
_TMP = tempfile.mkdtemp(prefix="av013-")
BASE_ENV = {
    "AGENTVERIFY_API_KEYS": KEY,
    "AGENTVERIFY_SIGNING_KEY_B64": SEED_B64,
    "AGENTVERIFY_USAGE_DB": os.path.join(_TMP, "usage.sqlite"),
    "AGENTVERIFY_RATE_LIMIT_PER_MINUTE": "100000",
}
CLAIM = {"calculation_type": "arithmetic", "claimed_result": "3", "inputs": {"a": "1", "b": "2"}}
BYPASS_FLAG = "AGENTVERIFY_I_ACCEPT_UNAUTHENTICATED_LOCAL_DEV_BYPASS"
DEV = {"AGENTVERIFY_LOCAL_DEV_MODE": "1", "AGENTVERIFY_LOCAL_BIND_HOST": "127.0.0.1"}


def set_env(**extra):
    for name in [n for n in os.environ if n.startswith("AGENTVERIFY_")]:
        del os.environ[name]
    for name in ("RENDER", "RENDER_SERVICE_ID", "DYNO", "K_SERVICE", "WEBSITE_INSTANCE_ID",
                 "AWS_LAMBDA_FUNCTION_NAME", "FORWARDED_ALLOW_IPS", "UVICORN_FORWARDED_ALLOW_IPS"):
        os.environ.pop(name, None)
    os.environ.update(BASE_ENV)
    os.environ.update(extra)


set_env()
from app import local_launch_guard  # noqa: E402
from app.main import app  # noqa: E402
import app.body_limit as body_limit  # noqa: E402
import app.local_dev_bypass as bypass  # noqa: E402
import app.mcp_hosts as mcp_hosts  # noqa: E402
import app.secure_launch as secure_launch  # noqa: E402
import app.security as security  # noqa: E402


def guard(active):
    if active:
        local_launch_guard.activate("127.0.0.1")
    else:
        local_launch_guard._guard_pid = None
        local_launch_guard._guard_host = None


async def _call(method, path, headers, body, chunks, client, server):
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method,
             "scheme": "http", "path": path, "raw_path": path.encode(), "query_string": b"",
             "root_path": "", "headers": headers, "client": client, "server": server}
    pending = list(chunks) if chunks is not None else [body]
    sent = []

    async def receive():
        if pending:
            part = pending.pop(0)
            return {"type": "http.request", "body": part, "more_body": bool(pending)}
        await asyncio.Event().wait()

    async def send(message):
        sent.append(message)

    await asyncio.wait_for(app(scope, receive, send), 20)
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    return status, b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")


def call(method="POST", path="/verify", payload=None, *, key=None, extra=(), host="127.0.0.1:8000",
         client=("127.0.0.1", 50000), server=("127.0.0.1", 8000), raw=None, content_length=True,
         chunks=None):
    body = raw if raw is not None else (b"" if payload is None else json.dumps(payload).encode())
    headers = [(b"host", host.encode())]
    if key:
        headers.append((b"x-api-key", key.encode()))
    if body or chunks:
        headers.append((b"content-type", b"application/json"))
        if content_length and chunks is None:
            headers.append((b"content-length", str(len(body)).encode()))
    headers.extend((n.encode(), v.encode()) for n, v in extra)
    return asyncio.run(_call(method, path, headers, body, chunks, client, server))


class F01DevBypass(unittest.TestCase):
    def tearDown(self):
        guard(False)
        set_env()

    def run_probe(self, n=300, **kw):
        return [call(payload=CLAIM, **kw)[0] for _ in range(n)]

    def test_all_conditions_met_is_the_only_bypass(self):
        set_env(**DEV, **{BYPASS_FLAG: "1"})
        guard(True)
        self.assertEqual(call(payload=CLAIM)[0], 200)

    def test_dev_mode_without_ack_flag_gets_401_x300(self):
        set_env(**DEV)
        guard(True)
        self.assertEqual(set(self.run_probe()), {401})

    def test_ack_flag_without_guarded_launcher_gets_401_x300(self):
        set_env(**DEV, **{BYPASS_FLAG: "1"})
        guard(False)  # direct uvicorn launch: launcher never ran
        self.assertEqual(set(self.run_probe()), {401})

    def test_ack_flag_without_loopback_bind_declaration_never_200(self):
        for bind in ("", "0.0.0.0", "localhost", "::", "10.0.0.5"):
            set_env(AGENTVERIFY_LOCAL_DEV_MODE="1", AGENTVERIFY_LOCAL_BIND_HOST=bind, **{BYPASS_FLAG: "1"})
            guard(True)
            self.assertIn(call(payload=CLAIM)[0], (401, 503), bind)

    def test_flag_without_dev_mode_gets_401(self):
        set_env(**{BYPASS_FLAG: "1", "AGENTVERIFY_LOCAL_BIND_HOST": "127.0.0.1"})
        guard(True)
        self.assertEqual(call(payload=CLAIM)[0], 401)

    def test_hosting_markers_and_public_mode_block_bypass(self):
        for marker in ({"RENDER": "1"}, {"K_SERVICE": "x"}, {"AGENTVERIFY_PUBLIC_MODE": "1"},
                       {"AGENTVERIFY_CLOUD_MODE": "1"}, {"FORWARDED_ALLOW_IPS": "*"}):
            set_env(**DEV, **{BYPASS_FLAG: "1"})
            os.environ.update(marker)
            guard(True)
            self.assertNotEqual(call(payload=CLAIM)[0], 200, marker)

    def test_network_peer_listener_or_host_refused_even_when_enabled(self):
        set_env(**DEV, **{BYPASS_FLAG: "1"})
        guard(True)
        self.assertEqual(call(payload=CLAIM, client=("203.0.113.9", 4000))[0], 403)
        self.assertEqual(call(payload=CLAIM, server=("192.168.1.5", 8000))[0], 403)
        self.assertEqual(call(payload=CLAIM, host="evil.example")[0], 403)
        self.assertEqual(call(payload=CLAIM, client=("testclient", 50000))[0], 403)

    def test_every_proxy_style_header_refused_even_when_enabled(self):
        set_env(**DEV, **{BYPASS_FLAG: "1"})
        guard(True)
        for name in ("X-Real-IP", "X-Forwarded-Proto", "X-Forwarded-For", "X-Forwarded-Host",
                     "X-Forwarded-Port", "Via", "Forwarded", "X-Original-Forwarded-For"):
            self.assertEqual(call(payload=CLAIM, extra=[(name, "127.0.0.1")])[0], 403, name)

    def test_valid_key_still_works_when_bypass_not_enabled(self):
        set_env(**DEV)
        guard(True)
        self.assertEqual(call(payload=CLAIM, key=KEY)[0], 200)

    def test_launcher_enforces_loopback_single_worker_for_bypass(self):
        env = {**DEV, BYPASS_FLAG: "1"}
        self.assertEqual(secure_launch.launch_errors("127.0.0.1", env), [])
        self.assertIn("local_requires_loopback_listener", secure_launch.launch_errors("0.0.0.0", env))
        self.assertIn("guarded_local_reload_forbidden",
                      secure_launch.launch_errors("127.0.0.1", env, reload=True))
        self.assertIn("guarded_local_workers_forbidden",
                      secure_launch.launch_errors("127.0.0.1", env, workers=2))

    def test_bypass_enabled_pure_function(self):
        guard(True)
        self.assertTrue(bypass.bypass_enabled({**DEV, BYPASS_FLAG: "1"}))
        self.assertFalse(bypass.bypass_enabled(DEV))
        self.assertFalse(bypass.bypass_enabled({BYPASS_FLAG: "1"}))
        guard(False)
        self.assertFalse(bypass.bypass_enabled({**DEV, BYPASS_FLAG: "1"}))


class F02BodyLimit(unittest.TestCase):
    def setUp(self):
        set_env()

    def test_oversized_content_length_gets_413_without_echo(self):
        marker = "ECHO_MARKER_" + "x" * 70000
        status, body = call(payload={**CLAIM, "extra": marker}, key=KEY)
        self.assertEqual(status, 413)
        self.assertNotIn(b"ECHO_MARKER", body)
        self.assertEqual(json.loads(body), {"detail": "Request body too large"})

    def test_oversized_413_is_returned_before_auth_work_on_unauthenticated_request(self):
        self.assertEqual(call(payload={**CLAIM, "extra": "y" * 70000})[0], 413)

    def test_oversized_chunked_body_gets_413(self):
        chunks = [b"{" + b'"a":1,' * 7000] + [b'"b":' + b"1" * 30000 + b"}"]
        status, body = call(chunks=chunks, key=KEY)
        self.assertEqual(status, 413)
        self.assertNotIn(b'"a":1', body)

    def test_small_chunked_body_is_replayed_intact(self):
        raw = json.dumps(CLAIM).encode()
        self.assertEqual(call(chunks=[raw[:10], raw[10:]], key=KEY)[0], 200)

    def test_legitimate_batch_of_50_still_works(self):
        item = {"calculation_type": "arithmetic", "claimed_result": "30000000000000000",
                "inputs": {"a": "10000000000000000", "b": "20000000000000000"}, "tolerance": "0.01"}
        payload = {"requests": [item] * 50}
        raw = json.dumps(payload).encode()
        self.assertLess(len(raw), body_limit.DEFAULT_MAX_BODY_BYTES)
        status, body = call("POST", "/verify/batch", payload, key=KEY)
        self.assertEqual(status, 200, body[:200])
        self.assertEqual(json.loads(body)["total"], 50)

    def test_batch_atomicity_any_invalid_item_is_422(self):
        bad = {"calculation_type": "arithmetic", "claimed_result": "NaN", "inputs": {"a": "1", "b": "2"}}
        status, _ = call("POST", "/verify/batch", {"requests": [CLAIM, bad, CLAIM]}, key=KEY)
        self.assertEqual(status, 422)

    def test_limit_is_configurable_and_invalid_values_fall_back_to_default(self):
        os.environ["AGENTVERIFY_MAX_BODY_BYTES"] = "2048"
        self.assertEqual(call(payload={**CLAIM, "e": "z" * 3000}, key=KEY)[0], 413)
        self.assertEqual(call(payload=CLAIM, key=KEY)[0], 200)
        for bad in ("abc", "0", "-5", "999999999999", ""):
            self.assertEqual(body_limit.max_body_bytes({"AGENTVERIFY_MAX_BODY_BYTES": bad}),
                             body_limit.DEFAULT_MAX_BODY_BYTES, bad)
        self.assertEqual(body_limit.max_body_bytes({}), 65536)

    def test_invalid_or_duplicate_content_length_is_400(self):
        self.assertEqual(call(payload=CLAIM, key=KEY, content_length=False,
                              extra=[("Content-Length", "12abc")])[0], 400)
        self.assertEqual(call(payload=CLAIM, key=KEY, content_length=False,
                              extra=[("Content-Length", "5"), ("Content-Length", "5")])[0], 400)

    def test_422_echo_is_bounded_by_the_cap(self):
        # 422 bodies still echo input (unchanged, pilot asserts the generic path);
        # the cap bounds the amplification to roughly the cap itself.
        status, body = call(payload={**CLAIM, "extra": "q" * 60000}, key=KEY)
        self.assertEqual(status, 422)
        self.assertLess(len(body), 2 * body_limit.DEFAULT_MAX_BODY_BYTES)


class F06Receipts(unittest.TestCase):
    def setUp(self):
        set_env()

    def test_rule_version_matches_api_version(self):
        status, body = call("POST", "/verify/signed", CLAIM, key=KEY)
        self.assertEqual(status, 200)
        receipt = json.loads(body)
        self.assertEqual(app.version, "0.8.0")
        self.assertEqual(receipt["payload"]["rule_version"], "agentverify-" + app.version)

    def test_client_verifier_and_server_check_still_accept_and_reject(self):
        from agentverify_client.receipts import verify_receipt
        receipt = json.loads(call("POST", "/verify/signed", CLAIM, key=KEY)[1])
        trusted = json.loads(call("GET", "/receipts/public-key", key=KEY)[1])["public_key"]
        self.assertTrue(verify_receipt(receipt, trusted))
        self.assertEqual(json.loads(call("POST", "/receipts/check", receipt, key=KEY)[1]), {"valid": True})
        receipt["payload"]["rule_version"] = "agentverify-0.3.0"
        self.assertFalse(verify_receipt(receipt, trusted))
        self.assertEqual(json.loads(call("POST", "/receipts/check", receipt, key=KEY)[1]), {"valid": False})

    def test_public_key_endpoint_still_requires_auth(self):
        self.assertEqual(call("GET", "/receipts/public-key")[0], 401)

    def test_mcp_hosts_default_is_localhost_only_and_env_driven(self):
        hosts, origins = mcp_hosts.allowed_hosts_and_origins({})
        self.assertEqual(hosts, ["127.0.0.1:*", "localhost:*", "[::1]:*"])
        self.assertFalse(any("onrender" in x for x in hosts + origins))
        hosts, origins = mcp_hosts.allowed_hosts_and_origins(
            {"AGENTVERIFY_MCP_ALLOWED_HOSTS": "verify.example.org, Other.example.org:8443"})
        self.assertIn("verify.example.org", hosts)
        self.assertIn("other.example.org:8443", hosts)
        self.assertIn("https://verify.example.org", origins)
        for bad in ("*", "*.example.org", "a b", "evil.com/x", "http://x.org", "-x.org"):
            with self.assertRaises(RuntimeError, msg=bad):
                mcp_hosts.allowed_hosts_and_origins({"AGENTVERIFY_MCP_ALLOWED_HOSTS": bad})

    def test_no_hardcoded_public_host_in_app_source(self):
        for path in (ROOT / "app").glob("*.py"):
            self.assertNotIn("onrender", path.read_text(encoding="utf-8"), path.name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
