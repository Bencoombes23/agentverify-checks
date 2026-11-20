"""AV-013 (F01): fail-closed conditions for the unauthenticated local-development bypass.

The bypass is reachable only when ALL of these hold:
  1. AGENTVERIFY_LOCAL_DEV_MODE=1
  2. the loudly named acknowledgement flag below is set to 1
  3. AGENTVERIFY_LOCAL_BIND_HOST is an explicit loopback address
  4. the process was started by the guarded launcher (app.secure_launch), which
     refused any non-loopback listener, reload and multiple workers
  5. no hosting / public / cloud marker and no wildcard forwarded-ip trust
and, per request: loopback peer, loopback listener address, loopback Host and
no proxy-style header. Anything else falls through to normal API-key auth.

Residual risk (documented): a same-host reverse proxy that strips every
proxy header is indistinguishable from a local client. Never run the bypass
behind a proxy.
"""
import os

from app.startup_policy import HOSTING_MARKERS, PROXY_MARKERS, canonical_listener

BYPASS_ACK_ENV = "AGENTVERIFY_I_ACCEPT_UNAUTHENTICATED_LOCAL_DEV_BYPASS"
LOOPBACK_ADDRESSES = ("127.0.0.1", "::1")
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")
_PROXY_HEADER_NAMES = frozenset((
    b"forwarded", b"via", b"x-real-ip", b"x-original-forwarded-for",
    b"x-client-ip", b"true-client-ip", b"cf-connecting-ip", b"x-cluster-client-ip",
    b"x-original-host", b"x-original-url", b"x-envoy-external-address",
))


def bypass_enabled(env=None) -> bool:
    """True only when every process-level condition is met (fail closed)."""
    e = os.environ if env is None else env
    if e.get("AGENTVERIFY_LOCAL_DEV_MODE") != "1" or e.get(BYPASS_ACK_ENV) != "1":
        return False
    if canonical_listener(e.get("AGENTVERIFY_LOCAL_BIND_HOST", "")) not in LOOPBACK_ADDRESSES:
        return False
    if any(e.get(k) for k in HOSTING_MARKERS):
        return False
    if e.get("AGENTVERIFY_PUBLIC_MODE") == "1" or e.get("AGENTVERIFY_CLOUD_MODE") == "1":
        return False
    if any(e.get(k) == "*" for k in PROXY_MARKERS):
        return False
    from app.local_launch_guard import guarded_local_process
    return guarded_local_process(e)


def proxy_header_present(raw_headers) -> bool:
    for name, _ in raw_headers:
        lowered = name.lower()
        if lowered in _PROXY_HEADER_NAMES or lowered.startswith(b"x-forwarded-"):
            return True
    return False


def loopback_request(scope) -> bool:
    """Peer, listener address and Host must all be loopback."""
    client = scope.get("client")
    server = scope.get("server")
    if not client or client[0] not in LOOPBACK_ADDRESSES:
        return False
    if not server or server[0] not in LOOPBACK_ADDRESSES:
        return False
    host = ""
    for name, value in scope.get("headers", ()):
        if name.lower() == b"host":
            host = value.decode("latin-1").strip().lower()
            break
    if host.startswith("["):
        host = host[1:].split("]", 1)[0]
    else:
        host = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
    return host in LOOPBACK_HOSTS
