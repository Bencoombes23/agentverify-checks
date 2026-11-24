"""Tests for the Apify Actor wrapper's pure logic (apify_actor.engine). No SDK, no network.

Run:  python -B tests_apify_actor.py
"""
import base64
import json
import os
import secrets
import sys
import unittest
from pathlib import Path

for _n in [n for n in os.environ if n.startswith("AGENTVERIFY_")]:
    del os.environ[_n]
os.environ["AGENTVERIFY_SIGNING_KEY_B64"] = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
sys.path.insert(0, str(Path(__file__).resolve().parent))

from agentverify_client import verify_receipt  # noqa: E402
from apify_actor.engine import EVENT_SIGNED_RECEIPT, EVENT_VERIFICATION, process_check  # noqa: E402
from app.receipts import public_key_info  # noqa: E402

PASS_PCT = {"calculation_type": "percentage", "claimed_result": "25", "inputs": {"part": "50", "whole": "200"}}
FAIL_PCT = {"calculation_type": "percentage", "claimed_result": "30", "inputs": {"part": "50", "whole": "200"}}
NUM_TEXT = {"calculation_type": "number_in_text", "claimed_result": "3200000", "unit": "$",
            "allow_scaling": True, "source_text": "Seed funding was $3.2m in 2025."}


class EngineTests(unittest.TestCase):
    def test_pass_is_billable(self):
        item, events = process_check(0, PASS_PCT, sign=False)
        self.assertEqual((item["index"], item["status"]), (0, "passed"))
        self.assertEqual(events, [EVENT_VERIFICATION])
        self.assertNotIn("receipt", item)

    def test_fail_is_a_real_result_and_billable(self):
        item, events = process_check(3, FAIL_PCT, sign=False)
        self.assertEqual(item["status"], "failed")
        self.assertEqual(events, [EVENT_VERIFICATION])

    def test_text_check_passes_and_item_is_json_serialisable(self):
        item, events = process_check(1, NUM_TEXT, sign=False)
        self.assertEqual(item["status"], "passed")
        json.dumps(item)
        self.assertEqual(events, [EVENT_VERIFICATION])

    def test_malformed_request_is_error_and_free(self):
        item, events = process_check(2, {"calculation_type": "nonsense"}, sign=False)
        self.assertEqual((item["status"], item["error"]), ("error", "invalid_request"))
        self.assertEqual(events, [])
        json.dumps(item)

    def test_non_object_is_error_and_free(self):
        item, events = process_check(0, "not an object", sign=False)
        self.assertEqual(item["status"], "error")
        self.assertEqual(events, [])

    def test_business_rule_rejection_is_error_and_free(self):
        zero = {"calculation_type": "divide", "claimed_result": "1", "inputs": {"a": "1", "b": "0"}}
        item, events = process_check(0, zero, sign=False)
        self.assertEqual((item["status"], item["error"]), ("error", "verification_error"))
        self.assertEqual(events, [])

    def test_signed_receipt_verifies_and_adds_event(self):
        item, events = process_check(0, NUM_TEXT, sign=True)
        self.assertEqual(events, [EVENT_VERIFICATION, EVENT_SIGNED_RECEIPT])
        key = public_key_info()["public_key"]
        self.assertTrue(verify_receipt(item["receipt"], key))
        self.assertNotIn("source_text", json.dumps(item["receipt"]))  # only its hash is signed
        tampered = json.loads(json.dumps(item["receipt"]))
        tampered["payload"]["result"]["status"] = "failed"
        self.assertFalse(verify_receipt(tampered, key))

    def test_error_rows_get_no_receipt(self):
        item, events = process_check(0, {"calculation_type": "nonsense"}, sign=True)
        self.assertNotIn("receipt", item)
        self.assertEqual(events, [])


class PackagingTests(unittest.TestCase):
    root = Path(__file__).resolve().parent

    def test_actor_json_points_at_real_files(self):
        actor = json.loads((self.root / ".actor" / "actor.json").read_text())
        self.assertEqual(actor["actorSpecification"], 1)
        for key in ("input", "dockerfile", "readme"):
            self.assertTrue((self.root / ".actor" / actor[key]).is_file(), key)
        self.assertTrue((self.root / ".actor" / actor["dockerContextDir"] / "apify_actor").is_dir())

    def test_input_schema_is_sane(self):
        schema = json.loads((self.root / ".actor" / "input_schema.json").read_text())
        self.assertEqual(schema["required"], ["checks"])
        self.assertTrue(schema["properties"]["signingKey"]["isSecret"])
        for prefill in schema["properties"]["checks"]["prefill"]:
            item, _ = process_check(0, prefill, sign=False)
            self.assertIn(item["status"], ("passed", "failed"))  # prefilled examples must be valid

    def test_dockerfile_copies_what_main_imports(self):
        text = (self.root / ".actor" / "Dockerfile").read_text()
        for needed in ("COPY app ./app", "COPY apify_actor ./apify_actor", "COPY agentverify_client", "requirements-actor.txt"):
            self.assertIn(needed, text)


if __name__ == "__main__":
    unittest.main()
