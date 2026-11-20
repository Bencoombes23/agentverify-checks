"""AV-018 claim-vs-source checks (stdlib only; the export has no pytest).

Run:  <venv python> -B tests_claimsource.py
Drives the real ASGI app directly (no sockets). Telemetry goes to a temp dir. All data synthetic.
"""
import asyncio
import hashlib
import json
import os
import random
import secrets
import sys
import tempfile
import unittest
from datetime import date, timedelta
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))

KEY = secrets.token_urlsafe(40)
_TMP = tempfile.mkdtemp(prefix="av018-")
for _n in [n for n in os.environ if n.startswith("AGENTVERIFY_")]:
    del os.environ[_n]
os.environ.update({
    "AGENTVERIFY_API_KEYS": KEY,
    "AGENTVERIFY_SIGNING_KEY_B64": "A" * 43,  # synthetic test seed only
    "AGENTVERIFY_USAGE_DB": os.path.join(_TMP, "usage.sqlite"),
    "AGENTVERIFY_RATE_LIMIT_PER_MINUTE": "100000",
})

from pydantic import ValidationError  # noqa: E402
from app.main import app  # noqa: E402
from app import textcheck  # noqa: E402
from app.models import VerificationRequest  # noqa: E402
from app.verifier import verify  # noqa: E402
import app.mcp_server as mcp_server  # noqa: E402


async def _call(method, path, headers, body):
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method,
             "scheme": "http", "path": path, "raw_path": path.encode(), "query_string": b"",
             "root_path": "", "headers": headers, "client": ("127.0.0.1", 50000),
             "server": ("127.0.0.1", 8000)}
    pending = [body]
    sent = []

    async def receive():
        if pending:
            return {"type": "http.request", "body": pending.pop(0), "more_body": False}
        await asyncio.Event().wait()

    async def send(message):
        sent.append(message)

    await asyncio.wait_for(app(scope, receive, send), 20)
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    return status, b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")


def call(method="POST", path="/verify", payload=None, key=KEY):
    body = b"" if payload is None else json.dumps(payload).encode()
    headers = [(b"host", b"127.0.0.1:8000")]
    if key:
        headers.append((b"x-api-key", key.encode()))
    if body:
        headers += [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]
    status, raw = asyncio.run(_call(method, path, headers, body))
    return status, (json.loads(raw) if raw else None)


def quote(claim, source, **kw):
    return {"calculation_type": "quote_in_text", "claim_text": claim, "source_text": source, **kw}


def number(claimed, source, **kw):
    return {"calculation_type": "number_in_text", "claimed_result": str(claimed), "source_text": source, **kw}


def datec(claim, source, **kw):
    return {"calculation_type": "date_in_text", "claim_text": claim, "source_text": source, **kw}


class Base(unittest.TestCase):
    def status_of(self, payload):
        status, body = call(payload=payload)
        self.assertEqual(status, 200, body)
        return body["status"]

    def assert_passes(self, payload):
        self.assertEqual(self.status_of(payload), "passed", payload)

    def assert_fails(self, payload):
        self.assertEqual(self.status_of(payload), "failed", payload)

    def assert_422(self, payload):
        self.assertEqual(call(payload=payload)[0], 422, payload)


class QuoteTests(Base):
    def test_exact_and_offset(self):
        status, body = call(payload=quote("brown fox", "The quick brown fox jumps"))
        self.assertEqual((status, body["status"]), (200, "passed"))
        self.assertEqual(body["evidence"]["match_offset"], 10)
        self.assertEqual(body["evidence"]["match_count"], 1)

    def test_not_found_with_hint(self):
        status, body = call(payload=quote("brown cat", "The quick brown fox"))
        self.assertEqual(body["status"], "failed")
        self.assertEqual(body["evidence"]["match_offset"], -1)
        self.assertEqual(body["evidence"]["closest_hint"]["longest_claim_prefix_chars"], 6)

    def test_unicode_quotes_dashes_whitespace(self):
        src = "She said “it’s a well—known fact”\n\n and   left."
        self.assert_passes(quote("\"it's a well-known fact\"", src))
        self.assert_passes(quote("‘it’s’", "x 'it's' y".replace("'it's'", "‘it’s’")))
        self.assert_passes(quote("fact\" and left.", src))  # whitespace collapse across newlines
        self.assert_passes(quote("a well-known", src))  # NBSP in claim
        self.assert_passes(quote("well–known", src))  # en dash vs em dash both map to '-'

    def test_nfc(self):
        self.assert_passes(quote("café society", "A café society met."))

    def test_case_flag(self):
        self.assert_fails(quote("BROWN FOX", "the brown fox"))
        self.assert_fails(quote("BROWN FOX", "the brown fox", case_insensitive=False))
        self.assert_passes(quote("BROWN FOX", "the brown fox", case_insensitive=True))

    def test_not_semantic(self):
        self.assert_fails(quote("the fast brown fox", "the quick brown fox"))

    def test_invalid_inputs_422(self):
        self.assert_422(quote("", "text"))
        self.assert_422(quote("ab", "abc def"))  # shorter than 3 chars
        self.assert_422(quote("abc", ""))
        self.assert_422(quote("abc", "   ​  "))  # empty after normalisation
        self.assert_422(quote("abc", "abc", extra_field=1))  # extra="forbid" still applies
        self.assert_422({"calculation_type": "quote_in_text", "claim_text": "abc"})  # no source
        self.assert_422(quote("abc", "abc", claimed_result="1"))
        self.assert_422(quote("abc", "abc", tolerance="0"))
        self.assert_422(quote("abc", "abc", inputs={"a": "1"}))
        self.assert_422(quote("abc", "abc", allow_scaling=True))
        self.assert_422(quote("x" * 2001, "abc"))
        self.assert_422(quote("abc", "abc \ud800"))  # lone surrogate must be 422, not 500

    def test_size_limits(self):
        with self.assertRaises(ValidationError):
            VerificationRequest.model_validate(quote("abc", "x" * 65537))
        VerificationRequest.model_validate(quote("abc", "x" * 65536))
        self.assert_passes(quote("needle", "hay " * 14000 + "needle"))  # ~56 KB over HTTP
        self.assertEqual(call(payload=quote("abc", "x" * 70000))[0], 413)  # AV-013 body cap first


class NumberTests(Base):
    def test_thousands_decimals(self):
        self.assert_passes(number("1234.5", "Revenue was 1,234.5 last year."))
        self.assert_passes(number("1234", "Revenue was 1,234 last year."))
        self.assert_passes(number("1234", "Revenue was 1234."))
        self.assert_fails(number("1234", "Revenue was 12345."))
        self.assert_fails(number("12345", "Revenue was 1234."))
        self.assert_fails(number("234", "Revenue was 1,234."))
        self.assert_fails(number("1234", "Revenue was 21234 or A1234 or 1234,5"))

    def test_trailing_zeros_numeric_equality(self):
        # Documented rule: numeric value equality, so 12.50 == 12.5.
        self.assert_passes(number("12.5", "price 12.50 today"))
        self.assert_passes(number("12.50", "price 12.5 today"))
        self.assert_fails(number("12.51", "price 12.5 today"))

    def test_near_miss_and_tolerance(self):
        body = call(payload=number("100", "we saw 100.4 units"))[1]
        self.assertEqual(body["status"], "failed")
        self.assertEqual(body["tolerance"], "0")  # default tolerance is 0 for this category
        self.assertEqual(body["calculated_result"], "100.4")
        self.assertEqual(body["difference"], "0.4")
        self.assert_passes(number("100", "we saw 100.4 units", tolerance="0.5"))
        self.assert_fails(number("100", "we saw 100.4 units", tolerance="0.3"))

    def test_percent_and_units(self):
        self.assert_passes(number("12", "grew 12% yearly"))
        self.assert_passes(number("12", "grew 12 % yearly", unit="%"))
        self.assert_fails(number("12", "grew 12 points", unit="%"))
        self.assert_passes(number("12", "cost $12 each", unit="$"))
        self.assert_fails(number("12", "cost 12 each", unit="$"))
        self.assert_passes(number("1200", "pay GBP 1,200 now", unit="GBP"))
        self.assert_passes(number("1200", "pay 1,200 gbp now", unit="GBP"))
        self.assert_fails(number("1200", "pay 1,200 gbps now", unit="GBP"))
        self.assert_passes(number("5", "weighs 5 kg", unit="kg"))

    def test_scaling_requires_flag(self):
        src = "Funding was $3.2m in 2025."
        self.assert_fails(number("3200000", src))
        self.assert_fails(number("3.2", src))  # 3.2m is not the standalone number 3.2
        self.assert_passes(number("3200000", src, allow_scaling=True))
        self.assert_passes(number("3200000", src, allow_scaling=True, unit="$"))
        self.assertEqual(call(payload=number("3200000", src, allow_scaling=True))[1]["calculated_result"],
                         "3200000")  # plain decimal, no E-notation
        self.assert_fails(number("3.2", src, allow_scaling=True))
        self.assert_passes(number("2000", "grew 2k users", allow_scaling=True))
        self.assert_passes(number("1500000000", "worth 1.5 billion", allow_scaling=True))
        self.assert_passes(number("1500000000", "worth 1.5bn", allow_scaling=True))
        self.assert_passes(number("5", "a 5 m wall"))  # spaced single letter is a unit, not a scale
        self.assert_passes(number("2025", src))

    def test_separators_and_malformed(self):
        self.assert_fails(number("1.2", "version 1.2.3"))
        self.assert_fails(number("123", "id 1,23"))
        self.assert_passes(number("5", "see (5), then 6."))
        self.assert_passes(number("-5", "change of -5 today"))
        self.assert_fails(number("5", "change of -5 today"))
        self.assert_passes(number("12", "pages 10-12"))
        self.assert_passes(number("-5", "net -$5"))
        self.assert_passes(number("1234", "Revenue was 1,234. Next"))

    def test_invalid_inputs_422(self):
        self.assert_422(number("NaN", "abc 1"))
        self.assert_422(number("1", ""))
        self.assert_422(number("1", "abc 1", unit="two words"))
        self.assert_422(number("1", "abc 1", unit="x1"))
        self.assert_422(number("1", "abc 1", unit="waytoolongunit"))
        self.assert_422(number("1", "abc 1", claim_text="1"))
        self.assert_422(number("1", "abc 1", case_insensitive=True))
        self.assert_422({"calculation_type": "number_in_text", "source_text": "1"})
        self.assert_422(number("1", "abc 1", inputs={"a": "1"}))
        self.assert_422(number("1", "no digits at all ​".replace("no digits at all", "   ")))


class DateTests(Base):
    TARGET = "2026-03-14"

    def test_documented_formats(self):
        for text in ("On 2026-03-14 we met", "On 14 March 2026 we met", "On 14th March 2026 we met",
                     "On 14 Mar 2026 we met", "On 14 Mar. 2026 we met", "On March 14, 2026 we met",
                     "On Mar 14 2026 we met", "On MARCH 14TH, 2026 we met", "On 2026–03–14 x"):
            self.assert_passes(datec(self.TARGET, text))
        self.assert_passes(datec("2026-09-05", "5 Sept 2026"))

    def test_wrong_dates_fail(self):
        for text in ("14 March 2025", "15 March 2026", "14 April 2026", "March 41, 2026",
                     "2026-03-140", "12026-03-14", "114 March 2026", "14 March 20266", "no date"):
            self.assert_fails(datec(self.TARGET, text))
        self.assert_fails(datec("2026-02-28", "31 February 2026"))

    def test_ambiguous_numeric_refused_unless_format_stated(self):
        text = "Signed 03/04/2026 and 03.04.2026."
        self.assert_fails(datec("2026-04-03", text))
        self.assert_fails(datec("2026-03-04", text))
        self.assert_passes(datec("2026-04-03", text, date_format="DMY"))
        self.assert_fails(datec("2026-03-04", text, date_format="DMY"))
        self.assert_passes(datec("2026-03-04", text, date_format="MDY"))
        self.assert_fails(datec("2026-04-03", text, date_format="MDY"))
        self.assert_passes(datec("2026-04-03", "Signed 2026/4/3.", date_format="YMD"))
        self.assert_fails(datec("2026-04-03", "Signed 2026/4/3."))
        self.assert_fails(datec("2026-04-03", "Signed 3/4/2026 mixed 3.4/2026", date_format="MDY"))

    def test_invalid_inputs_422(self):
        for bad in ("2026-3-14", "14 March 2026", "2026-02-30", "2026-13-01", "26-03-14", ""):
            self.assert_422(datec(bad, "x 2026-03-14"))
        self.assert_422(datec(self.TARGET, ""))
        self.assert_422(datec(self.TARGET, "x", case_insensitive=True))
        self.assert_422(datec(self.TARGET, "x", date_format="ISO"))
        self.assert_422(quote("abc", "abc", date_format="DMY"))


class ReceiptTests(Base):
    def issue(self, payload):
        status, receipt = call(path="/verify/signed", payload=payload)
        self.assertEqual(status, 200, receipt)
        pub = call("GET", "/receipts/public-key")[1]["public_key"]
        return receipt, pub

    def test_receipt_binds_claim_and_source_without_storing_source(self):
        from agentverify_client.receipts import verify_receipt
        source = "The  “Quick” fox\n— ran."
        receipt, pub = self.issue(quote("\"quick\" fox - ran", source, case_insensitive=True))
        self.assertTrue(verify_receipt(receipt, pub))
        payload = receipt["payload"]
        self.assertNotIn("source_text", payload["request"])
        self.assertNotIn("Quick", json.dumps(payload))
        expected = hashlib.sha256('the "quick" fox - ran.'.encode("utf-8")).hexdigest()
        evidence = payload["result"]["evidence"]
        self.assertEqual(evidence["source_sha256"], expected)
        self.assertEqual(evidence["normalisation"], {"version": "av-text-norm-1", "unicode": "NFC", "case_fold": True})
        self.assertEqual(payload["request"]["claim_text"], "\"quick\" fox - ran")
        self.assertEqual(payload["result"]["status"], "passed")
        # Third party with the same text re-derives the hash.
        self.assertEqual(textcheck.sha256_hex(textcheck.normalise(source, True)), expected)
        self.assertEqual(json.loads(json.dumps(call(path="/receipts/check", payload=receipt)[1])), {"valid": True})

    def test_tamper_fails(self):
        from agentverify_client.receipts import verify_receipt
        for payload in (quote("brown fox", "the brown fox"), number("5", "is 5"), datec("2026-03-14", "2026-03-14")):
            receipt, pub = self.issue(payload)
            self.assertTrue(verify_receipt(receipt, pub))
            for mutate in (
                lambda r: r["payload"]["result"]["evidence"].__setitem__("source_sha256", "0" * 64),
                lambda r: r["payload"]["result"].__setitem__("status", "failed"),
                lambda r: r["payload"]["request"].__setitem__("claim_text" if "claim_text" in r["payload"]["request"]
                                                                else "claimed_result", "9"),
                lambda r: r["payload"]["result"]["evidence"].__setitem__("match_offset", 99),
            ):
                bad = json.loads(json.dumps(receipt))
                mutate(bad)
                self.assertFalse(verify_receipt(bad, pub))
                self.assertEqual(call(path="/receipts/check", payload=bad)[1], {"valid": False})

    def test_number_receipt_shape(self):
        receipt, _ = self.issue(number("3200000", "got $3.2m", allow_scaling=True, unit="$"))
        req, res = receipt["payload"]["request"], receipt["payload"]["result"]
        self.assertEqual((req["allow_scaling"], req["unit"]), (True, "$"))
        self.assertEqual(res["evidence"]["allow_scaling"], True)
        self.assertEqual(res["tolerance"], "0")

    def test_arithmetic_receipt_and_response_unchanged_in_shape(self):
        claim = {"calculation_type": "arithmetic", "claimed_result": "3", "inputs": {"a": "1", "b": "2"}}
        status, body = call(payload=claim)
        self.assertEqual(status, 200)
        self.assertEqual(set(body), {"status", "calculation_type", "claimed_result", "calculated_result",
                                     "difference", "tolerance", "explanation"})
        receipt, _ = self.issue(claim)
        self.assertEqual(set(receipt["payload"]["request"]), {"calculation_type", "claimed_result", "inputs", "tolerance"})
        self.assertEqual(set(receipt["payload"]["result"]), set(body))

    def test_unsigned_auth_still_required(self):
        self.assertEqual(call(payload=quote("abc", "abc"), key=None)[0], 401)
        self.assertEqual(call(path="/verify/signed", payload=quote("abc", "abc"), key=None)[0], 401)


class BatchAndMixTests(Base):
    ARITH = {"calculation_type": "arithmetic", "claimed_result": "3", "inputs": {"a": "1", "b": "2"}}

    def test_mixed_batch(self):
        items = [self.ARITH, quote("brown fox", "the brown fox"), number("7", "has 8"),
                 datec("2026-03-14", "14 March 2026")]
        status, body = call(path="/verify/batch", payload={"requests": items})
        self.assertEqual(status, 200, body)
        self.assertEqual((body["total"], body["passed"], body["failed"]), (4, 3, 1))
        self.assertEqual([r["status"] for r in body["results"]], ["passed", "passed", "failed", "passed"])

    def test_batch_atomic_on_any_invalid(self):
        good = quote("brown fox", "the brown fox")
        for bad in (quote("", "x"), datec("2026-02-30", "x"), number("1", ""),
                    {**self.ARITH, "source_text": "x"},
                    quote("abc", "   "),  # fails after normalisation (verifier stage)
                    {"calculation_type": "arithmetic", "claimed_result": "3", "inputs": {}}):
            status, _ = call(path="/verify/batch", payload={"requests": [self.ARITH, good, bad, good]})
            self.assertEqual(status, 422, bad)

    def test_arithmetic_semantics_unchanged(self):
        status, body = call(payload={"calculation_type": "arithmetic", "claimed_result": "4",
                                     "inputs": {"a": "1", "b": "2"}})
        self.assertEqual((status, body["status"], body["calculated_result"]), (200, "failed", "3"))
        self.assertEqual(call(payload={"calculation_type": "arithmetic", "claimed_result": "3",
                                       "inputs": {"a": "1"}})[0], 422)
        self.assertEqual(call(payload={"calculation_type": "arithmetic", "inputs": {"a": "1", "b": "2"}})[0], 422)


class McpTests(unittest.TestCase):
    def test_mcp_paths(self):
        out = mcp_server.calculate(quote("brown fox", "the brown fox"))
        self.assertEqual(out["status"], "passed")
        self.assertNotIn("claimed_result", out)
        batch = mcp_server.calculate_batch([quote("zzz", "the brown fox"), number("5", "is 5")])
        self.assertEqual((batch["total"], batch["passed"], batch["failed"]), (2, 1, 1))
        receipt = mcp_server.calculate_signed(datec("2026-03-14", "14 March 2026"))
        self.assertEqual(receipt["payload"]["result"]["status"], "passed")
        self.assertTrue(mcp_server.check_signed_receipt(receipt)["valid"])
        self.assertEqual(mcp_server.calculate(quote("", "x"))["error"], "invalid_request")
        self.assertEqual(mcp_server.calculate(quote("abc", "  "))["error"], "verification_error")


class RandomisedSelfConsistency(unittest.TestCase):
    WORDS = ("alpha beta gamma delta river stone cloud market policy report growth review team "
             "budget plan north south value method sample result trend board paper study").split()
    MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September",
              "October", "November", "December"]

    def run_one(self, payload):
        return verify(VerificationRequest.model_validate(payload)).status

    def filler(self, rng, n):
        return " ".join(rng.choice(self.WORDS) for _ in range(n))

    def test_500_texts(self):
        rng = random.Random(20260101)
        for i in range(500):
            # --- quote: alter exactly one character to '#', which never occurs in the text
            quote_words = " ".join(rng.choice(self.WORDS) + str(rng.choice("abcxyz")) for _ in range(rng.randint(2, 5)))
            text = f"{self.filler(rng, rng.randint(0, 40))} {quote_words} {self.filler(rng, rng.randint(0, 40))}."
            self.assertEqual(self.run_one(quote(quote_words, text)), "passed", i)
            pos = rng.randrange(len(quote_words))
            altered = quote_words[:pos] + "#" + quote_words[pos + 1:]
            if altered.strip() and altered != quote_words:
                self.assertEqual(self.run_one(quote(altered, text)), "failed", (i, altered))
            # --- number: alter one digit; the text contains no other numbers
            value = rng.randint(1, 10 ** rng.randint(1, 9))
            style = rng.choice(["{:,}", "{}", "{:,}.50", "${:,}", "{:,}%"])
            shown = style.format(value)
            text = f"{self.filler(rng, 10)} was {shown} overall, {self.filler(rng, 10)}."
            claimed = str(value) + (".5" if ".50" in style else "")
            self.assertEqual(self.run_one(number(claimed, text)), "passed", (i, shown))
            digits = list(str(value))
            k = rng.randrange(len(digits))
            digits[k] = str((int(digits[k]) + rng.randint(1, 9)) % 10)
            altered_value = "".join(digits).lstrip("0") or "0"
            if altered_value != str(value):
                altered_claim = altered_value + (".5" if ".50" in style else "")
                self.assertEqual(self.run_one(number(altered_claim, text)), "failed", (i, shown, altered_claim))
            # --- date: any rendered format passes; neighbouring day fails
            d = date(2000, 1, 1) + timedelta(days=rng.randrange(9000))
            fmt = rng.choice(["{y}-{m:02d}-{dd:02d}", "{dd} {mn} {y}", "{mn} {dd}, {y}", "{dd}th {mn} {y}"])
            rendered = fmt.format(y=d.year, m=d.month, dd=d.day, mn=self.MONTHS[d.month - 1])
            text = f"{self.filler(rng, 8)} on {rendered} the {self.filler(rng, 8)}."
            self.assertEqual(self.run_one(datec(d.isoformat(), text)), "passed", (i, rendered))
            other = d + timedelta(days=rng.choice([-1, 1]))
            self.assertEqual(self.run_one(datec(other.isoformat(), text)), "failed", (i, rendered, other))


if __name__ == "__main__":
    unittest.main(verbosity=1)
