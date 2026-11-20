"""AV-017: optional x402 pay-per-call gate (EXPERIMENTAL, TESTNET-ONLY, OFF BY DEFAULT).

When AGENTVERIFY_X402_ENABLED is not "1"/"true" this module is inert: the middleware
forwards every request untouched and the x402 package is never imported.

When enabled, a request to a paid route (POST /verify, /verify/batch, /verify/signed)
that carries NO X-API-Key header must carry a valid x402 v2 payment (PAYMENT-SIGNATURE).
It is verified, the route runs, and the payment is settled only if the route returned 200
(a 422/4xx/5xx is never charged). A request that carries an X-API-Key header always goes
through the unchanged API-key path (valid key: served free; invalid key: 401).

Nothing here logs, stores or echoes payment headers or payloads. Replay protection keys
are one-way hashes. No private key, seed or wallet is ever read.
"""
import hashlib
import logging
import os
import re
import threading
import time
from collections import deque
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from urllib.parse import urlsplit

logger = logging.getLogger("agentverify.x402")

# Mirrors x402.http.constants.DEFAULT_FACILITATOR_URL (a test asserts they match). It is the
# public TESTNET facilitator; it is not a production/mainnet facilitator.
DEFAULT_FACILITATOR_URL = "https://x402.org/facilitator"
DEFAULT_NETWORK = "eip155:84532"  # Base Sepolia (testnet) per the x402 package README/constants
DEFAULT_PRICE = "0.001"  # USD, paid in USDC
MAX_PRICE = Decimal("10")
# Networks that are known TESTNETS with a default USDC asset in the x402 package
# (Base Sepolia, Arbitrum Sepolia). Everything else is treated as mainnet-class.
TESTNET_NETWORKS = frozenset({"eip155:84532", "eip155:421614"})
PAID_ROUTES = frozenset({("POST", "/verify"), ("POST", "/verify/batch"), ("POST", "/verify/signed")})
PAID_FLAG = "agentverify.x402_paid"  # ASGI scope key; set only by this gate, never by a client
REF_HEADER = "X-AgentVerify-Payment-Ref"
_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
_NETWORK = re.compile(r"^eip155:[0-9]{1,12}$")
_TRUE, _FALSE = {"1", "true"}, {"", "0", "false"}


class X402ConfigError(RuntimeError):
    """Safe configuration failure; messages never contain configured values."""


@dataclass(frozen=True)
class X402Config:
    pay_to: str
    network: str
    price: str
    facilitator_url: str
    mainnet: bool


def enabled(env=None) -> bool:
    raw = (os.environ if env is None else env).get("AGENTVERIFY_X402_ENABLED", "")
    return raw.strip().lower() in _TRUE


def config_errors(env=None) -> list:
    """Generic, value-free error strings. Empty list when x402 is off or valid."""
    e = os.environ if env is None else env
    flag = e.get("AGENTVERIFY_X402_ENABLED", "").strip().lower()
    if flag in _FALSE:
        return []
    if flag not in _TRUE:
        return ["x402 enable flag invalid"]
    errors = []
    pay_to = e.get("AGENTVERIFY_X402_PAY_TO", "").strip()
    if not _ADDRESS.match(pay_to) or int(pay_to[2:], 16) == 0:
        errors.append("x402 pay-to address missing or malformed")
    network = e.get("AGENTVERIFY_X402_NETWORK", DEFAULT_NETWORK).strip()
    if not _NETWORK.match(network):
        errors.append("x402 network invalid")
    price = e.get("AGENTVERIFY_X402_PRICE", DEFAULT_PRICE).strip()
    try:
        value = Decimal(price)
        if not (0 < value <= MAX_PRICE) or value.as_tuple().exponent < -6 or not value.is_finite():
            raise InvalidOperation
    except (InvalidOperation, ValueError):
        errors.append("x402 price invalid")
    raw_url = e.get("AGENTVERIFY_X402_FACILITATOR_URL", "").strip()
    url = raw_url or DEFAULT_FACILITATOR_URL
    parts = urlsplit(url)
    loopback = parts.hostname in ("127.0.0.1", "localhost", "::1")
    if (parts.scheme not in ("https", "http") or not parts.hostname or "@" in parts.netloc
            or parts.query or parts.fragment or (parts.scheme == "http" and not loopback)):
        errors.append("x402 facilitator url invalid")
    if network not in TESTNET_NETWORKS and _NETWORK.match(network):
        is_default = url.rstrip("/").lower() == DEFAULT_FACILITATOR_URL
        if e.get("AGENTVERIFY_X402_ALLOW_MAINNET") != "1":
            errors.append("x402 mainnet network refused without AGENTVERIFY_X402_ALLOW_MAINNET=1")
        if not raw_url or is_default:
            errors.append("x402 mainnet requires an explicit non-default facilitator url")
    return errors


def parse_config(env=None) -> X402Config:
    e = os.environ if env is None else env
    if not enabled(e):
        raise X402ConfigError("x402 disabled")
    if config_errors(e):
        raise X402ConfigError("x402 configuration invalid")
    network = e.get("AGENTVERIFY_X402_NETWORK", DEFAULT_NETWORK).strip()
    return X402Config(
        pay_to=e["AGENTVERIFY_X402_PAY_TO"].strip(),
        network=network,
        price=e.get("AGENTVERIFY_X402_PRICE", DEFAULT_PRICE).strip(),
        facilitator_url=(e.get("AGENTVERIFY_X402_FACILITATOR_URL", "").strip() or DEFAULT_FACILITATOR_URL),
        mainnet=network not in TESTNET_NETWORKS,
    )


class ReplayGuard:
    """In-process one-time-use registry for payment proofs (hashed keys only).

    HONEST LIMIT: state is per process and is lost on restart; it is not shared between
    workers/instances. The facilitator/chain (EIP-3009 nonce) is the durable double-spend
    protection; this guard additionally stops reuse of one proof for a second *request*.
    """
    INFLIGHT_SECONDS = 120
    CONSUMED_SECONDS = 24 * 3600
    MAX_ENTRIES = 100_000

    def __init__(self):
        self._lock = threading.Lock()
        self._entries = {}  # key -> (state, expires_monotonic)
        self._calls = 0

    def reserve(self, keys) -> bool:
        now = time.monotonic()
        with self._lock:
            self._calls += 1
            if self._calls % 256 == 0:  # amortised purge of expired entries
                for key in [k for k, (_, exp) in self._entries.items() if exp <= now]:
                    del self._entries[key]
            if any(k in self._entries and self._entries[k][1] > now for k in keys):
                return False
            while len(self._entries) + len(keys) > self.MAX_ENTRIES:
                self._entries.pop(next(iter(self._entries)))
            for key in keys:
                self._entries[key] = ("inflight", now + self.INFLIGHT_SECONDS)
            return True

    def consume(self, keys):
        now = time.monotonic()
        with self._lock:
            for key in keys:
                self._entries[key] = ("consumed", now + self.CONSUMED_SECONDS)

    def release(self, keys):
        with self._lock:
            for key in keys:
                if self._entries.get(key, ("", 0))[0] == "inflight":
                    del self._entries[key]


class _Limiter:
    """Global cap on payment-bearing requests per minute (protects the facilitator)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._hits = deque()

    def allow(self, env=None) -> bool:
        try:
            limit = int((os.environ if env is None else env).get("AGENTVERIFY_X402_MAX_VERIFY_PER_MINUTE", "120"))
            if not 1 <= limit <= 100000:
                raise ValueError
        except ValueError:
            limit = 120
        now = time.monotonic()
        with self._lock:
            while self._hits and self._hits[0] <= now - 60:
                self._hits.popleft()
            if len(self._hits) >= limit:
                return False
            self._hits.append(now)
            return True


_replay = ReplayGuard()
_limiter = _Limiter()
_cache = {"key": None, "middleware": None}
_cache_lock = threading.Lock()


def reset_for_tests():
    global _replay, _limiter
    _replay, _limiter = ReplayGuard(), _Limiter()
    with _cache_lock:
        _cache["key"] = _cache["middleware"] = None


def _make_facilitator(cfg: X402Config):
    from x402.http import FacilitatorConfig, HTTPFacilitatorClient
    return HTTPFacilitatorClient(FacilitatorConfig(url=cfg.facilitator_url, timeout=15.0))


def _build_middleware(cfg: X402Config):
    from x402 import x402ResourceServer
    from x402.http.middleware.fastapi import payment_middleware
    from x402.mechanisms.evm.exact import ExactEvmServerScheme
    server = x402ResourceServer(_make_facilitator(cfg))
    server.register("eip155:*", ExactEvmServerScheme())
    accepts = {"scheme": "exact", "payTo": cfg.pay_to, "price": "$" + cfg.price,
               "network": cfg.network, "maxTimeoutSeconds": 60}
    routes = {f"{verb} {path}": {"accepts": dict(accepts), "mimeType": "application/json",
                                  "description": f"AgentVerify deterministic check ({path})"}
              for verb, path in sorted(PAID_ROUTES)}
    # Lazy facilitator sync (done here, with the documented initialize()/get_supported_kind(),
    # rather than via sync_facilitator_on_start, which os._exit()s the process on a capability
    # mismatch). An outage raises -> 503 and is NOT cached, so the next paid request retries.
    server.initialize()
    if not server.get_supported_kind(2, cfg.network, "exact"):
        raise X402ConfigError("facilitator does not support the configured network")
    return payment_middleware(routes, server, sync_facilitator_on_start=False)


def _get_middleware(cfg: X402Config):
    key = (cfg, id(_make_facilitator))
    with _cache_lock:
        if _cache["key"] != key:
            _cache["middleware"] = _build_middleware(cfg)
            _cache["key"] = key
        return _cache["middleware"]


def replay_keys(header_values):
    """One-way keys identifying a payment proof (never the proof itself)."""
    keys = set()
    for raw in header_values:
        text = raw.decode("latin-1") if isinstance(raw, bytes) else raw
        keys.add("h:" + hashlib.sha256(text.encode("latin-1", "replace")).hexdigest())
        try:
            from x402.http.utils import decode_payment_signature_header
            inner = getattr(decode_payment_signature_header(text), "payload", None) or {}
            auth = inner.get("authorization") or inner.get("permit2Authorization") or {}
            nonce = auth.get("nonce")
            if nonce:
                payer = str(auth.get("from") or (auth.get("witness") or {}).get("from") or "")
                keys.add("n:" + hashlib.sha256(f"{payer.lower()}|{nonce}".encode()).hexdigest())
        except Exception:
            pass  # undecodable header: the package will treat it as no payment
    return sorted(keys)


def pricing_info(env=None):
    """Public discovery data for /pricing when x402 is enabled and valid, else None."""
    e = os.environ if env is None else env
    if not enabled(e) or config_errors(e):
        return None
    cfg = parse_config(e)
    return {"network": cfg.network, "price_usd": cfg.price, "testnet": not cfg.mainnet,
            "paid_routes": sorted(f"{v} {p}" for v, p in PAID_ROUTES),
            "api_key_bypass": True, "status": "experimental"}


async def _json(send, status, body_obj, extra=()):
    import json
    body = json.dumps(body_obj).encode()
    await send({"type": "http.response.start", "status": status, "headers": [
        (b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
        *extra]})
    await send({"type": "http.response.body", "body": body})


class X402GateMiddleware:
    """Pure ASGI. Inert (a direct pass-through) unless enabled and the route is paid."""

    def __init__(self, app):
        self.app = app

    def _applies(self, scope) -> bool:
        if scope["type"] != "http" or not enabled():
            return False
        if (scope["method"], scope["path"]) not in PAID_ROUTES:
            return False
        return not any(n.lower() == b"x-api-key" for n, _ in scope["headers"])

    async def __call__(self, scope, receive, send):
        if not self._applies(scope):
            return await self.app(scope, receive, send)
        if config_errors():
            return await _json(send, 503, {"detail": "x402 configuration invalid"})
        pay_names = (b"payment-signature", b"x-payment")
        pay_values = [v for n, v in scope["headers"] if n.lower() in pay_names]
        if pay_values and not _limiter.allow():
            return await _json(send, 429, {"detail": "Payment verification rate limit exceeded"},
                               [(b"retry-after", b"60")])
        keys = replay_keys(pay_values) if pay_values else []
        replayed = bool(keys) and not _replay.reserve(keys)
        # A replayed proof is treated as "no payment": fresh requirements, error overridden below.
        inner_scope = dict(scope)
        inner_scope["headers"] = [(n, v) for n, v in scope["headers"]
                                  if not (replayed and n.lower() in pay_names)]
        outcome = {"served": False, "raised": False}
        try:
            response = await self._run(inner_scope, receive, outcome)
        except Exception:
            _replay.release(keys)
            logger.warning("x402 request failed closed (%s)", "handler" if outcome["raised"] else "payment")
            return await _json(send, 500 if outcome["raised"] else 503,
                               {"detail": "Internal Server Error" if outcome["raised"]
                                else "Payment service unavailable"})
        if replayed:
            logger.info("x402 payment proof reuse rejected")
            from starlette.responses import JSONResponse
            headers = {k: v for k, v in response.headers.items() if k.lower() != "content-length"}
            response = JSONResponse({"error": "payment_already_used"}, status_code=402, headers=headers)
        elif keys:
            settled = outcome["served"] and response.status_code == 200 and "payment-response" in response.headers
            if settled:
                _replay.consume(keys)
                self._add_reference(response)
            else:
                _replay.release(keys)
        await response(scope, receive, send)

    async def _run(self, scope, receive, outcome):
        import asyncio
        from starlette.requests import Request
        # Blocking facilitator fetch (cold start only) runs off the event loop.
        middleware = await asyncio.to_thread(_get_middleware, parse_config())
        request = Request(scope, receive)

        async def call_next(req):
            if getattr(req.state, "payment_payload", None) is None:
                from starlette.responses import JSONResponse
                return JSONResponse({"error": "Payment required"}, status_code=402)  # fail closed
            req.scope[PAID_FLAG] = True
            outcome["served"] = True
            try:
                return await self._call_inner(req.scope, receive)
            except Exception:
                outcome["raised"] = True
                raise

        return await middleware(request, call_next)

    async def _call_inner(self, scope, receive):
        from starlette.responses import StreamingResponse
        messages = []

        async def capture(message):
            messages.append(message)

        await self.app(scope, receive, capture)
        start = next(m for m in messages if m["type"] == "http.response.start")
        body = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")

        async def one():
            yield body

        response = StreamingResponse(one(), status_code=start["status"])
        response.raw_headers = list(start["headers"])
        response.__dict__.pop("_headers", None)
        return response

    @staticmethod
    def _add_reference(response):
        try:
            from x402.http.utils import decode_payment_response_header
            settle = decode_payment_response_header(response.headers["payment-response"])
            if settle.success and settle.transaction:
                response.headers[REF_HEADER] = f"{settle.network}:{settle.transaction}"
        except Exception:
            pass
