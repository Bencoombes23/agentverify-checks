"""Versioned client-side receipt verification; independent of server trust state."""
import base64
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

CLIENT_TRUST_VERSION = "1"


def _decode(value):
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    if len(raw) != 32:
        raise ValueError("Expected 32-byte Ed25519 public key")
    return raw


def issuer_fingerprint(public_key):
    return hashlib.sha256(_decode(public_key)).hexdigest()


def _canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def verify_receipt(receipt, trusted_public_key):
    try:
        if set(receipt) != {"payload", "algorithm", "public_key", "signature"}:
            return False
        if receipt["algorithm"] != "Ed25519" or receipt["public_key"] != trusted_public_key:
            return False
        signature = base64.b64decode(receipt["signature"] + "=" * (-len(receipt["signature"]) % 4),
                                     altchars=b"-_", validate=True)
        Ed25519PublicKey.from_public_bytes(_decode(trusted_public_key)).verify(
            signature, _canonical(receipt["payload"]))
        return True
    except (InvalidSignature, KeyError, TypeError, ValueError, RecursionError):
        return False


class IssuerTrustStore:
    def __init__(self, pins=None):
        self._pins = {}
        for public_key, status in (pins or {}).items():
            self.pin(public_key, status=status)

    def pin(self, public_key, *, status="active"):
        if status not in {"active", "retired", "revoked"}:
            raise ValueError("Invalid issuer status")
        fingerprint = issuer_fingerprint(public_key)
        current = self._pins.get(fingerprint)
        if current is not None and current["status"] == "revoked" and status != "revoked":
            raise ValueError("Revocation is terminal")
        self._pins[fingerprint] = {"public_key": public_key, "status": status}
        return fingerprint

    def set_status(self, fingerprint, status):
        if status not in {"active", "retired", "revoked"}:
            raise ValueError("Invalid issuer status")
        pin = self._pins[fingerprint]
        if pin["status"] == "revoked" and status != "revoked":
            raise ValueError("Revocation is terminal")
        pin["status"] = status

    def verify(self, receipt):
        try:
            pin = self._pins[issuer_fingerprint(receipt["public_key"])]
            return pin["status"] in {"active", "retired"} and verify_receipt(
                receipt, pin["public_key"])
        except (KeyError, TypeError, ValueError, RecursionError):
            return False

    def manifest(self):
        return {key: value.copy() for key, value in sorted(self._pins.items())}
