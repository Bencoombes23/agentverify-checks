"""AV-017 checks for the optional x402 pay-per-call gate (stdlib only; no network, no funds).

Run:  <venv python> -B tests_x402.py
Uses a FAKE in-process facilitator and synthetic placeholder values only: the pay-to value
below is an obviously fake address, signatures are zero bytes, no key or wallet is involved.
Drives the real ASGI app directly (no sockets). Telemetry goes to a temp dir.

The testnet integration test at the bottom is SKIPPED unless
AGENTVERIFY_X402_RUN_TESTNET_INTEGRATION=1 (it needs network; it never needs funds or keys).
"""
import asyncio
import base64
import json
import logging
import os
import secrets
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))

KEY = secrets.token_urlsafe(40)
PAY_TO = "0x" + "1" * 40  # synthetic placeholder, not a real wallet
PAYER = "0x" + "2" * 40  # synthetic placeholder
_TMP = tempfile.mkdtemp(prefix="av017-")
BASE_ENV = {
    "AGENTVERIFY_API_KEYS": KEY,
    "AGENTVERIFY_SIGNING_KEY_B64": "A" * 43,  # synthetic zero seed, tests only
    "AGENTVERIFY_USAGE_DB": os.path.join(_TMP, "usage.sqlite"),
    "AGENTVERIFY_RATE_LIMIT_PER_MINUTE": "100000",
}
X402_ENV = {"AGENTVERIFY_X402_ENABLED": "1", "AGENTVERIFY_X402_PAY_TO": PAY_TO}
CLAIM = {"calculation_type": "arithmetic", "claimed_result": "3", "inputs": {"a": "1", "b": "2"}}
BAD_BATCH = {"requests": [CLAIM, {"calculation_type": "arithmetic", "claimed_result": "NaN",
                                  "inputs": {"a": "1", "b": "2"}}]}
LEGACY_PRICING = {"mode": "free", "currency": "USD", "price_per_verification": "0",
                  "payment_required": False, "x402_enabled": False,
                  "note": "All verification endpoints are free. No real payments are accepted."}


def set_env(**extra):
    for name in [n for n in os.environ if n.startswith("AGENTVERIFY_")]:
        del os.environ[name]
    for name in ("RENDER", "RENDER_SERVICE_ID", "DYNO", "K_SERVICE", "WEBSITE_INSTANCE_ID",
                 "AWS_LAMBDA_FUNCTION_NAME", "FORWARDED_ALLOW_IPS", "UVICORN_FORWARDED_ALLOW_IPS"):
        os.environ.pop(name, None)
    os.environ.update(BASE_ENV)
    os.environ.update(extra)


set_env()
from app.main import app  # noqa: E402
import app.x402_gate as gate  # noqa: E402
from app.startup import StartupValidationError, build_config  # noqa: E402

from x402.http.utils import (  # noqa: E402
    decode_payment_required_header, decode_payment_response_header, encode_payment_signature_header)
from x402.schemas import (  # noqa: E402
    PaymentPayload, SettleResponse, SupportedKind, SupportedResponse, VerifyResponse)

TX = "0x" + "ab" * 32


class FakeFacilitator:
    """In-process stand-in for a facilitator. It deliberately does NOT track nonces, so any
    replay rejection seen in the tests is performed by AgentVerify, not by the fake."""

    def __init__(self, network="eip155:84532"):
        self.network = network
        self.verify_calls = self.settle_calls = 0
        self.down = self.supported_down = self.settle_fails = False

    def get_supported(self):
        if self.supported_down:
            raise ConnectionError("facilitator unreachable")
        return SupportedResponse(kinds=[SupportedKind(x402_version=2, scheme="exact", network=self.network)])

    async def verify(self, payload, requirements):
        self.verify_calls += 1
        if self.down:
            raise ConnectionError("facilitator unreachable")
        auth = payload.payload["authorization"]
        if int(auth["validBefore"]) < time.time():
            return VerifyResponse(is_valid=False, invalid_reason="invalid_exact_evm_authorization_expired")
        if payload.payload.get("signature") != "0x" + "00" * 65:
            return VerifyResponse(is_valid=False, invalid_reason="invalid_exact_evm_signature")
        return VerifyResponse(is_valid=True, payer=auth["from"])

    async def settle(self, payload, requirements):
        self.settle_calls += 1
        if self.settle_fails:
            return SettleResponse(success=False, error_reason="settle_failed", transaction="",
                                  network=requirements.network)
        return SettleResponse(success=True, payer=PAYER, transaction=TX, network=requirements.network)


async def _call(method, path, headers, body):
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method,
             "scheme": "http", "path": path, "raw_path": path.encode(), "query_string": b"",
             "root_path": "", "headers": headers, "client": ("127.0.0.1", 50000), "server": ("127.0.0.1", 8000)}
    pending, sent = [body], []

    async def receive():
        if pending:
            return {"type": "http.request", "body": pending.pop(0), "more_body": False}
        await asyncio.Event().wait()

    async def send(message):
        sent.append(message)

    await asyncio.wait_for(app(scope, receive, send), 20)
    start = next(m for m in sent if m["type"] == "http.response.start")
    headers_out = {k.decode().lower(): v.decode("latin-1") for k, v in start["headers"]}
    return start["status"], headers_out, b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")


def call(method="POST", path="/verify", payload=None, *, key=None, pay=None, extra=()):
    body = b"" if payload is None else json.dumps(payload).encode()
    headers = [(b"host", b"127.0.0.1:8000")]
    if key:
        headers.append((b"x-api-key", key.encode()))
    if pay:
        headers.append((b"payment-signature", pay.encode()))
    if body:
        headers += [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]
    headers.extend((n.encode(), v.encode()) for n, v in extra)
    return asyncio.run(_call(method, path, headers, body))


def requirements_for(path="/verify"):
    status, headers, _ = call(path=path, payload=CLAIM)
    assert status == 402, status
    return decode_payment_required_header(headers["payment-required"])


def make_payment(path="/verify", nonce=None, valid_for=60, signature="0x" + "00" * 65):
    required = requirements_for(path)
    auth = {"from": PAYER, "to": PAY_TO, "value": required.accepts[0].amount,
            "validBefore": str(int(time.time()) + valid_for), "nonce": nonce or "0x" + secrets.token_hex(32)}
    payload = PaymentPayload(x402_version=2, payload={"authorization": auth, "signature": signature},
                             accepted=required.accepts[0], resource=required.resource)
    return encode_payment_signature_header(payload)


class X402Base(unittest.TestCase):
    ENV = X402_ENV

    def setUp(self):
        set_env(**self.ENV)
        self.fake = FakeFacilitator()
        gate._make_facilitator = lambda cfg, fake=self.fake: fake
        gate.reset_for_tests()

    def tearDown(self):
        set_env()
        gate.reset_for_tests()


class DisabledByDefault(unittest.TestCase):
    def setUp(self):
        set_env()

    def test_existing_behaviour_unchanged_when_disabled(self):
        self.assertEqual(call(payload=CLAIM)[0], 401)  # no key: still 401, never 402
        self.assertEqual(call(payload=CLAIM, pay="x")[0], 401)
        self.assertEqual(call(payload=CLAIM, key=KEY)[0], 200)
        status, _, body = call("GET", "/pricing")
        self.assertEqual((status, json.loads(body)), (200, LEGACY_PRICING))
        self.assertEqual(call("GET", "/health")[0], 200)

    def test_disabled_values_are_inert_and_package_not_imported(self):
        for value in ("", "0", "false", "FALSE"):
            self.assertFalse(gate.enabled({"AGENTVERIFY_X402_ENABLED": value}))
            self.assertEqual(gate.config_errors({"AGENTVERIFY_X402_ENABLED": value}), [])
        code = ("import sys, os; sys.path.insert(0, %r); from app.main import app; "
                "assert not any(m == 'x402' or m.startswith('x402.') for m in sys.modules); print('inert')" % str(ROOT))
        env = {k: v for k, v in os.environ.items() if not k.startswith("AGENTVERIFY_X402")}
        out = subprocess.run([sys.executable, "-B", "-c", code], env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(out.stdout.strip(), "inert", out.stderr[-400:])

    def test_invalid_enable_flag_refuses_rather_than_guessing(self):
        self.assertEqual(gate.config_errors({"AGENTVERIFY_X402_ENABLED": "yes"}), ["x402 enable flag invalid"])

    def test_default_facilitator_matches_package_constant(self):
        from x402.http.constants import DEFAULT_FACILITATOR_URL
        self.assertEqual(gate.DEFAULT_FACILITATOR_URL, DEFAULT_FACILITATOR_URL)


class Requirements402(X402Base):
    def test_no_key_no_payment_gets_402_with_correct_requirements(self):
        for path in ("/verify", "/verify/batch", "/verify/signed"):
            payload = {"requests": [CLAIM]} if path.endswith("batch") else CLAIM
            status, headers, _ = call(path=path, payload=payload)
            self.assertEqual(status, 402, path)
            required = decode_payment_required_header(headers["payment-required"])
            accept = required.accepts[0]
            self.assertEqual((accept.scheme, accept.network, accept.pay_to, accept.amount),
                             ("exact", "eip155:84532", PAY_TO, "1000"), path)  # $0.001 USDC, 6 decimals
            self.assertTrue(accept.asset)
        self.assertEqual(self.fake.settle_calls, 0)

    def test_price_is_configurable(self):
        set_env(**X402_ENV, AGENTVERIFY_X402_PRICE="0.002")
        self.assertEqual(requirements_for().accepts[0].amount, "2000")

    def test_unpaid_discovery_and_non_paid_routes_are_untouched(self):
        self.assertEqual(call("GET", "/health")[0], 200)
        status, _, body = call("GET", "/pricing")
        info = json.loads(body)
        self.assertEqual((status, info["x402_enabled"], info["x402"]["network"]), (200, True, "eip155:84532"))
        self.assertNotIn(PAY_TO, body.decode())
        self.assertEqual(call("GET", "/receipts/public-key")[0], 401)  # not a paid route: key only
        self.assertEqual(call("POST", "/receipts/check", {"a": 1})[0], 401)

    def test_oversized_body_still_413_before_any_payment_work(self):
        self.assertEqual(call(payload={**CLAIM, "extra": "y" * 70000})[0], 413)


class PaidFlow(X402Base):
    def test_valid_payment_served_once_then_proof_rejected(self):
        pay = make_payment()
        status, headers, body = call(payload=CLAIM, pay=pay)
        self.assertEqual(status, 200, body[:300])
        self.assertEqual(json.loads(body)["status"], "passed")
        settle = decode_payment_response_header(headers["payment-response"])
        self.assertTrue(settle.success)
        self.assertEqual(headers[gate.REF_HEADER.lower()], f"eip155:84532:{TX}")
        self.assertEqual((self.fake.verify_calls, self.fake.settle_calls), (1, 1))
        status, headers, body = call(payload=CLAIM, pay=pay)  # same proof again
        self.assertEqual(status, 402)
        self.assertEqual(json.loads(body), {"error": "payment_already_used"})
        self.assertIn("payment-required", headers)  # client can pay afresh
        self.assertEqual((self.fake.verify_calls, self.fake.settle_calls), (1, 1))  # no second charge/verify

    def test_same_nonce_in_a_re_signed_proof_is_also_rejected(self):
        nonce = "0x" + secrets.token_hex(32)
        self.assertEqual(call(payload=CLAIM, pay=make_payment(nonce=nonce))[0], 200)
        again = make_payment(nonce=nonce, valid_for=61)  # different bytes, same nonce
        self.assertEqual(call(payload=CLAIM, pay=again)[0], 402)
        self.assertEqual(self.fake.settle_calls, 1)

    def test_signed_receipt_is_unchanged_and_verifiable_when_paid(self):
        from agentverify_client.receipts import verify_receipt
        status, headers, body = call(path="/verify/signed", payload=CLAIM, pay=make_payment("/verify/signed"))
        self.assertEqual(status, 200)
        receipt = json.loads(body)
        self.assertEqual(set(receipt), {"payload", "algorithm", "public_key", "signature"})  # no added field
        self.assertTrue(verify_receipt(receipt, receipt["public_key"]))
        self.assertIn(gate.REF_HEADER.lower(), headers)  # payment reference is a separate header
        keyed = json.loads(call(path="/verify/signed", payload=CLAIM, key=KEY)[2])
        self.assertEqual(set(keyed), set(receipt))

    def test_batch_is_priced_per_call_and_served(self):
        status, _, body = call(path="/verify/batch", payload={"requests": [CLAIM] * 5},
                               pay=make_payment("/verify/batch"))
        self.assertEqual((status, json.loads(body)["total"], self.fake.settle_calls), (200, 5, 1))

    def test_invalid_or_expired_payment_gets_402_and_is_not_charged(self):
        for kind, pay in (("expired", make_payment(valid_for=-30)),
                          ("bad signature", make_payment(signature="0x" + "11" * 65)),
                          ("garbage", "not-base64-%%%"),
                          ("wrong structure", base64.b64encode(b'{"x402Version":2}').decode())):
            status, headers, _ = call(payload=CLAIM, pay=pay)
            self.assertEqual(status, 402, kind)
            self.assertIn("payment-required", headers, kind)
        self.assertEqual(self.fake.settle_calls, 0)

    def test_failed_payment_does_not_burn_the_proof(self):
        pay = make_payment()
        self.fake.down = True
        self.assertEqual(call(payload=CLAIM, pay=pay)[0], 402)
        self.fake.down = False
        self.assertEqual(call(payload=CLAIM, pay=pay)[0], 200)

    def test_422_requests_are_not_charged_and_proof_stays_usable(self):
        pay = make_payment("/verify/batch")
        status, headers, _ = call(path="/verify/batch", payload=BAD_BATCH, pay=pay)
        self.assertEqual(status, 422)
        self.assertNotIn("payment-response", headers)
        self.assertEqual(self.fake.settle_calls, 0)
        self.assertEqual(call(path="/verify/batch", payload={"requests": [CLAIM]}, pay=pay)[0], 200)
        self.assertEqual(self.fake.settle_calls, 1)
        status, _, _ = call(payload={"calculation_type": "arithmetic"}, pay=make_payment())
        self.assertEqual((status, self.fake.settle_calls), (422, 1))

    def test_payment_rate_limit_protects_the_facilitator(self):
        set_env(**X402_ENV, AGENTVERIFY_X402_MAX_VERIFY_PER_MINUTE="2")
        statuses = [call(payload=CLAIM, pay="junk%d" % i)[0] for i in range(3)]
        self.assertEqual(statuses, [402, 402, 429])


class FailClosed(X402Base):
    def test_facilitator_down_at_verify_never_serves(self):
        self.fake.down = True
        status, _, body = call(payload=CLAIM, pay=make_payment())
        self.assertIn(status, (402, 503))
        self.assertNotEqual(status, 200)
        self.assertNotIn(b'"status"', body)
        self.assertEqual(self.fake.settle_calls, 0)

    def test_facilitator_down_at_startup_sync_gives_503_then_recovers(self):
        self.fake.supported_down = True
        self.assertEqual(call(payload=CLAIM)[0], 503)
        self.fake.supported_down = False
        self.assertEqual(call(payload=CLAIM)[0], 402)

    def test_settlement_failure_is_not_a_free_pass(self):
        self.fake.settle_fails = True
        status, _, body = call(payload=CLAIM, pay=make_payment())
        self.assertEqual(status, 402)
        self.assertNotIn(b'"status"', body)


class ApiKeyPath(X402Base):
    def test_valid_key_bypasses_payment(self):
        for path, payload in (("/verify", CLAIM), ("/verify/signed", CLAIM), ("/verify/batch", {"requests": [CLAIM]})):
            self.assertEqual(call(path=path, payload=payload, key=KEY)[0], 200, path)
        self.assertEqual((self.fake.verify_calls, self.fake.settle_calls), (0, 0))

    def test_invalid_key_is_401_even_with_a_valid_payment_and_no_fallback(self):
        pay = make_payment()
        self.assertEqual(call(payload=CLAIM, key="x" * 40, pay=pay)[0], 401)
        self.assertEqual((self.fake.verify_calls, self.fake.settle_calls), (0, 0))

    def test_clients_cannot_forge_the_paid_flag(self):
        for name in ("agentverify.x402_paid", "agentverify-x402-paid", "x-agentverify-x402-paid"):
            self.assertEqual(call(payload=CLAIM, extra=[(name, "True")])[0], 402, name)
        set_env()
        self.assertEqual(call(payload=CLAIM, extra=[("agentverify.x402_paid", "True")])[0], 401)


class SafetyRails(unittest.TestCase):
    def tearDown(self):
        set_env()
        gate.reset_for_tests()

    def errors(self, **extra):
        return gate.config_errors({**X402_ENV, **extra})

    def test_valid_testnet_default_config(self):
        self.assertEqual(self.errors(), [])
        cfg = gate.parse_config({**X402_ENV})
        self.assertEqual((cfg.network, cfg.price, cfg.facilitator_url, cfg.mainnet),
                         ("eip155:84532", "0.001", gate.DEFAULT_FACILITATOR_URL, False))

    def test_missing_or_malformed_pay_to_is_refused(self):
        env = {"AGENTVERIFY_X402_ENABLED": "1"}
        self.assertTrue(gate.config_errors(env))
        for bad in ("", "0x", "0x123", "0x" + "g" * 40, "0x" + "1" * 41, "1" * 40, "0x" + "0" * 40, " "):
            self.assertTrue(self.errors(AGENTVERIFY_X402_PAY_TO=bad), repr(bad))

    def test_pay_to_failure_refuses_startup_and_serves_503(self):
        set_env(AGENTVERIFY_X402_ENABLED="1", AGENTVERIFY_X402_PAY_TO="0xnotanaddress")
        with self.assertRaises(StartupValidationError):
            build_config()
        self.assertEqual(call(payload=CLAIM)[0], 503)
        self.assertEqual(call(payload=CLAIM, key=KEY)[0], 503)  # whole deployment fails closed
        set_env(**X402_ENV)
        build_config()  # valid config starts

    def test_mainnet_is_refused_without_both_extra_flags(self):
        main = {"AGENTVERIFY_X402_NETWORK": "eip155:8453"}
        other = {"AGENTVERIFY_X402_FACILITATOR_URL": "https://facilitator.example.org"}
        self.assertTrue(self.errors(**main))
        self.assertTrue(self.errors(**main, AGENTVERIFY_X402_ALLOW_MAINNET="1"))  # default facilitator
        self.assertTrue(self.errors(**main, **other))  # no allow flag
        self.assertTrue(self.errors(**main, AGENTVERIFY_X402_ALLOW_MAINNET="1",
                                    AGENTVERIFY_X402_FACILITATOR_URL=gate.DEFAULT_FACILITATOR_URL + "/"))
        self.assertTrue(self.errors(**main, AGENTVERIFY_X402_ALLOW_MAINNET="true", **other))  # exactly "1"
        self.assertEqual(self.errors(**main, AGENTVERIFY_X402_ALLOW_MAINNET="1", **other), [])
        for unknown in ("eip155:1", "eip155:137", "eip155:99999"):  # unknown networks are mainnet-class
            self.assertTrue(self.errors(AGENTVERIFY_X402_NETWORK=unknown), unknown)
        for bad in ("solana:devnet", "base-sepolia", "eip155:", "eip155:8453 "[:-1] + "x"):
            self.assertTrue(self.errors(AGENTVERIFY_X402_NETWORK=bad), bad)

    def test_mainnet_config_refuses_startup_and_never_serves(self):
        set_env(**X402_ENV, AGENTVERIFY_X402_NETWORK="eip155:8453")
        with self.assertRaises(StartupValidationError):
            build_config()
        self.assertEqual(call(payload=CLAIM)[0], 503)

    def test_price_and_facilitator_url_validation(self):
        for bad in ("0", "-1", "abc", "0.0000001", "11", "NaN", "Infinity", ""):
            self.assertTrue(self.errors(AGENTVERIFY_X402_PRICE=bad), repr(bad))
        for good in ("0.001", "1", "0.000001", "10"):
            self.assertEqual(self.errors(AGENTVERIFY_X402_PRICE=good), [], good)
        for bad in ("http://facilitator.example.org", "ftp://x.org", "https://user:pw@x.org",
                    "https://x.org/?k=1", "not a url", "https://"):
            self.assertTrue(self.errors(AGENTVERIFY_X402_FACILITATOR_URL=bad), bad)
        self.assertEqual(self.errors(AGENTVERIFY_X402_FACILITATOR_URL="http://127.0.0.1:4402"), [])

    def test_error_messages_never_contain_configured_values(self):
        secret_like = "0xSECRETISH" + "q" * 20
        text = " ".join(self.errors(AGENTVERIFY_X402_PAY_TO=secret_like))
        self.assertNotIn("SECRETISH", text)


class NoLeakage(X402Base):
    def test_payment_headers_and_payloads_never_reach_logs(self):
        records = []

        class Capture(logging.Handler):
            def emit(self, record):
                records.append(self.format(record) + " " + str(record.exc_text) + " " + str(record.args))

        handler, root = Capture(), logging.getLogger()
        old_level = root.level
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        try:
            good = make_payment()
            expired = make_payment(valid_for=-30)
            call(payload=CLAIM, pay=good)
            call(payload=CLAIM, pay=good)  # replay
            call(payload=CLAIM, pay=expired)
            self.fake.down = True
            call(payload=CLAIM, pay=make_payment())  # facilitator error path
            self.fake.down = False
            self.fake.settle_fails = True
            call(payload=CLAIM, pay=make_payment())
        finally:
            root.removeHandler(handler)
            root.setLevel(old_level)
        joined = "\n".join(records)
        for secret in (good, expired, PAYER, "0x" + "00" * 65):
            self.assertNotIn(secret, joined)
        self.assertNotIn(KEY, joined)


@unittest.skipUnless(os.environ.get("AGENTVERIFY_X402_RUN_TESTNET_INTEGRATION") == "1",
                     "network integration test: skipped by default (no network, no funds, no keys used)")
class TestnetIntegration(unittest.TestCase):
    def test_public_testnet_facilitator_lists_base_sepolia(self):
        from x402.http import HTTPFacilitatorClientSync
        supported = HTTPFacilitatorClientSync().get_supported()
        self.assertIn("eip155:84532", {kind.network for kind in supported.kinds})


if __name__ == "__main__":
    unittest.main(verbosity=2)
