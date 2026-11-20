"""Research-only extra validation for local-development server startup.

This checks configuration supplied to the guarded launcher. It cannot attest
that an external proxy, container, or operating system actually binds loopback.
"""
from __future__ import annotations

import ipaddress
from typing import Mapping

LOOPBACK = frozenset(('127.0.0.1', '::1'))
HOSTING_MARKERS = ('RENDER', 'RENDER_SERVICE_ID', 'DYNO', 'K_SERVICE',
                   'WEBSITE_INSTANCE_ID', 'AWS_LAMBDA_FUNCTION_NAME')
PROXY_MARKERS = ('FORWARDED_ALLOW_IPS', 'UVICORN_FORWARDED_ALLOW_IPS')

def canonical_listener(value: str) -> str | None:
    """Accept only explicit canonical IPv4/IPv6 addresses, never DNS names."""
    if not isinstance(value, str) or not value or value != value.strip():
        return None
    candidate = value[1:-1] if value.startswith('[') and value.endswith(']') else value
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    if '%' in candidate or address.is_multicast or address.is_unspecified:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return None
    return str(address)

def local_startup_errors(host: str, env: Mapping[str, str], *, reload: bool = False,
                         workers: int = 1) -> list[str]:
    """Safe error codes; no values from env are included in diagnostics."""
    if env.get('AGENTVERIFY_LOCAL_DEV_MODE') != '1':
        return []
    errors: list[str] = []
    actual = canonical_listener(host)
    declared = canonical_listener(env.get('AGENTVERIFY_LOCAL_BIND_HOST', ''))
    if actual not in LOOPBACK:
        errors.append('local_listener_not_explicit_loopback')
    if declared != actual or declared not in LOOPBACK:
        errors.append('local_listener_declaration_invalid')
    if reload:
        errors.append('local_reload_not_supported')
    if workers != 1:
        errors.append('local_requires_single_worker')
    if env.get('AGENTVERIFY_PUBLIC_MODE') == '1' or env.get('AGENTVERIFY_CLOUD_MODE') == '1' or any(env.get(x) for x in HOSTING_MARKERS):
        errors.append('local_conflicts_with_public_hosting')
    if any(env.get(x) == '*' for x in PROXY_MARKERS):
        errors.append('local_wildcard_forwarded_trust')
    return errors
