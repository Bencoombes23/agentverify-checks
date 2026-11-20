"""Research-only pure policy for deciding whether a local auth bypass is eligible.

Not wired into production middleware. No request Host/X-Forwarded-* header is
accepted as evidence of the actual listener address.
"""
from __future__ import annotations
from collections.abc import Mapping
from app.startup_policy import canonical_listener, HOSTING_MARKERS


def local_bypass_eligible(env: Mapping[str, str], *, guarded: bool, listener: str | None) -> bool:
    """Fail closed unless explicitly enabled, guarded, and exact loopback."""
    if env.get('AGENTVERIFY_LOCAL_DEV_MODE') != '1':
        return False
    if env.get('AGENTVERIFY_REQUIRE_GUARDED_LOCAL_LAUNCH') != '1':
        return False
    if not guarded:
        return False
    if any(env.get(marker) for marker in HOSTING_MARKERS):
        return False
    if env.get('AGENTVERIFY_PUBLIC_MODE') == '1' or env.get('AGENTVERIFY_CLOUD_MODE') == '1':
        return False
    if any(env.get(marker) == '*' for marker in ('FORWARDED_ALLOW_IPS', 'UVICORN_FORWARDED_ALLOW_IPS')):
        return False
    if canonical_listener(listener) not in ('127.0.0.1', '::1'):
        return False
    return canonical_listener(env.get('AGENTVERIFY_LOCAL_BIND_HOST')) == canonical_listener(listener)
