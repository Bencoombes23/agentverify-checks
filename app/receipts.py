"""Local-development Ed25519 receipts. Not a production trust service."""
import base64
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

from app import __version__

KEY_DIR = Path(__file__).resolve().parent.parent / ".agentverify"
KEY_FILE = KEY_DIR / "signing_key.pem"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(data: str) -> bytes:
    return base64.b64decode(data + "=" * (-len(data) % 4), altchars=b"-_", validate=True)


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")



def _cloud_key() -> Ed25519PrivateKey | None:
    """Load stable 32-byte Ed25519 seed from base64url environment secret."""
    raw = os.getenv("AGENTVERIFY_SIGNING_KEY_B64", "")
    if not raw:
        if os.getenv("AGENTVERIFY_CLOUD_MODE") == "1" or os.getenv("AGENTVERIFY_LOCAL_DEV_MODE") != "1":
            raise RuntimeError("AGENTVERIFY_SIGNING_KEY_B64 is required outside local development")
        return None
    try:
        seed = _unb64(raw)
        if len(seed) != 32:
            raise ValueError("Expected 32 bytes")
        return Ed25519PrivateKey.from_private_bytes(seed)
    except (ValueError, TypeError) as exc:
        raise RuntimeError("Invalid AGENTVERIFY_SIGNING_KEY_B64; expected base64url of 32 random bytes") from exc


def validate_cloud_config() -> None:
    """Fail before serving traffic if Render test mode is unsafe."""
    if os.getenv("AGENTVERIFY_CLOUD_MODE") != "1":
        return
    if os.getenv("AGENTVERIFY_PUBLIC_MODE") != "1":
        raise RuntimeError("Cloud mode requires AGENTVERIFY_PUBLIC_MODE=1")
    from app.credentials import backend_name, configuration_errors
    if backend_name() == "legacy":
        keys = [k.strip() for k in os.getenv("AGENTVERIFY_API_KEYS", "").split(",") if k.strip()]
        if not keys or any(len(k) < 32 for k in keys):
            raise RuntimeError("Cloud mode requires strong AGENTVERIFY_API_KEYS")
    elif configuration_errors():
        raise RuntimeError("Cloud mode requires valid durable credential configuration")
    if os.getenv("AGENTVERIFY_DEV_PAYMENT_PREVIEW") == "1":
        raise RuntimeError("Disable payment preview in cloud mode")
    try:
        limit = int(os.getenv("AGENTVERIFY_RATE_LIMIT_PER_MINUTE", "60"))
    except ValueError as exc:
        raise RuntimeError("Invalid rate limit") from exc
    if not 1 <= limit <= 100000:
        raise RuntimeError("Invalid rate limit")
    _cloud_key()

def _private_key() -> Ed25519PrivateKey:
    cloud = _cloud_key()
    if cloud is not None:
        return cloud
    KEY_DIR.mkdir(exist_ok=True)
    if not KEY_FILE.exists():
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        # Exclusive creation avoids silently replacing an existing key.
        try:
            with KEY_FILE.open("xb") as f:
                f.write(pem)
        except FileExistsError:
            pass
        if os.name != "nt":
            KEY_FILE.chmod(0o600)
    return serialization.load_pem_private_key(KEY_FILE.read_bytes(), password=None)


def public_key_info() -> dict:
    raw = _private_key().public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {"algorithm": "Ed25519", "public_key": _b64(raw)}


def issue_receipt(request, result) -> dict:
    key = _private_key()
    payload = {
        "receipt_version": "1",
        "receipt_id": str(uuid4()),
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "rule_version": "agentverify-" + __version__,
        # exclude_none keeps arithmetic receipts byte-identical to pre-AV-018. The full source
        # text is never stored: result.evidence carries its SHA-256 and the normalisation flags.
        "request": request.model_dump(mode="json", exclude_none=True, exclude={"source_text"}),
        "result": result.model_dump(mode="json", exclude_none=True),
    }
    return {
        "payload": payload,
        "algorithm": "Ed25519",
        "public_key": _b64(key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )),
        "signature": _b64(key.sign(_canonical(payload))),
    }


def check_receipt(receipt: dict) -> bool:
    try:
        if set(receipt) != {"payload", "algorithm", "public_key", "signature"}:
            return False
        if receipt["algorithm"] != "Ed25519":
            return False
        # Compare to our configured issuer, not an attacker-supplied key alone.
        if receipt["public_key"] != public_key_info()["public_key"]:
            return False
        pub = Ed25519PublicKey.from_public_bytes(_unb64(receipt["public_key"]))
        pub.verify(_unb64(receipt["signature"]), _canonical(receipt["payload"]))
        return True
    except (ValueError, TypeError, KeyError, InvalidSignature, RecursionError):
        return False

# Validate at import time, before the ASGI application accepts requests.
validate_cloud_config()

