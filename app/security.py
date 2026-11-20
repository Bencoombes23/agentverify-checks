"""API-key authentication, pseudonymous attribution, optional atomic quotas."""
import hashlib
import hmac
import os
import threading
import time
from collections import defaultdict, deque
from contextvars import ContextVar

from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

customer_context = ContextVar("agentverify_customer", default=None)
idempotency_context = ContextVar("agentverify_idempotency", default=None)
_lock = threading.Lock()
_hits = defaultdict(deque)

def reset_rate_limits():
    with _lock:
        _hits.clear()

def customer_id(key: str) -> str:
    secret = os.getenv("AGENTVERIFY_CUSTOMER_ID_SECRET", "")
    if len(secret) < 32:
        raise ValueError("AGENTVERIFY_CUSTOMER_ID_SECRET must be at least 32 characters")
    return hmac.new(secret.encode(), key.encode(), hashlib.sha256).hexdigest()

class APIProtectionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        # V1.80: deployment configuration gate (fail closed, no secret disclosure).
        from app.deployment_config import deployment_errors
        if deployment_errors():
            return JSONResponse(status_code=503, content={"detail": "Deployment security configuration invalid"})
        idempotency_values = [
            value for name, value in request.scope["headers"]
            if name.lower() == b"idempotency-key"
        ]
        if idempotency_values and (request.url.path != "/verify/signed" or request.method != "POST"):
            return JSONResponse(status_code=400, content={"detail": "Invalid idempotency request"})
        # V2.60: separate opt-in strict-local policy; disabled by default.
        # This is process-local guard evidence, NOT proof of OS socket binding.
        if os.getenv("AGENTVERIFY_AUTH_STRICT_LOCAL_V260") == "1" and os.getenv("AGENTVERIFY_LOCAL_DEV_MODE") == "1":
            from app.auth_boundary_policy import local_bypass_eligible
            from app.local_launch_guard import guarded_local_process
            env = dict(os.environ)
            if not local_bypass_eligible(env, guarded=guarded_local_process(),
                                         listener=env.get("AGENTVERIFY_LOCAL_BIND_HOST")):
                return JSONResponse(status_code=503, content={"detail": "Strict local authentication boundary invalid"})
        # V2.30: opt-in fail-closed application boundary, including direct ASGI launch.
        # Does not prove OS socket binding. Production configuration remains unchanged.
        if os.getenv("AGENTVERIFY_AUTH_BOUNDARY_V230") == "1" and os.getenv("AGENTVERIFY_LOCAL_DEV_MODE") == "1":
            from app.auth_boundary_policy import local_bypass_eligible
            from app.local_launch_guard import guarded_local_process
            env = dict(os.environ)
            if not local_bypass_eligible(env, guarded=guarded_local_process(),
                                         listener=env.get("AGENTVERIFY_LOCAL_BIND_HOST")):
                return JSONResponse(status_code=503, content={"detail": "Local authentication boundary invalid"})
        # V1.90: optional process-local launcher proof for local bypass.
        # This is not a substitute for OS/network listener restrictions.
        from app.local_launch_guard import guarded_local_process
        if (os.getenv("AGENTVERIFY_LOCAL_DEV_MODE") == "1" and
                os.getenv("AGENTVERIFY_REQUIRE_GUARDED_LOCAL_LAUNCH") == "1" and
                not guarded_local_process()):
            return JSONResponse(status_code=503, content={"detail": "Guarded local launch required"})
        # AV-013 (F01): the unauthenticated local-dev bypass is fail closed. It needs
        # dev mode AND an explicit acknowledgement flag AND a loopback bind AND the
        # guarded launcher (see app.local_dev_bypass). Otherwise normal auth applies.
        from app.local_dev_bypass import bypass_enabled, loopback_request, proxy_header_present
        if bypass_enabled():
            if not loopback_request(request.scope) or proxy_header_present(request.scope["headers"]):
                return JSONResponse(status_code=403, content={"detail": "Local development mode requires loopback access"})
            if idempotency_values:
                return JSONResponse(status_code=400, content={"detail": "Idempotency is unavailable for this request"})
            return await call_next(request)
        # AV-017: the x402 gate verified a payment for this request. The flag lives in the ASGI
        # scope, which only server-side code can set (clients cannot inject scope keys).
        if request.scope.get("agentverify.x402_paid") is True:
            if idempotency_values:
                return JSONResponse(status_code=400, content={"detail": "Idempotency is unavailable for this request"})
            if request.url.path == "/verify/signed" and not os.getenv("AGENTVERIFY_SIGNING_KEY_B64"):
                return JSONResponse(status_code=503, content={"detail": "Signing key is not configured"})
            return await call_next(request)
        # Missing credentials/configuration returns 503 below; never bypass.
        if request.url.path in ("/health", "/pricing") and request.method == "GET":
            return await call_next(request)
        from app.credentials import backend_name
        credential_backend = backend_name()
        keys = [k.strip() for k in os.getenv("AGENTVERIFY_API_KEYS", "").split(",") if k.strip()]
        if credential_backend == "legacy" and (not keys or any(len(k) < 32 for k in keys)):
            return JSONResponse(status_code=503, content={"detail": "API authentication is not configured"})
        # Signing requires a stable issuer key outside explicit local development.
        if request.url.path == "/verify/signed" and not os.getenv("AGENTVERIFY_SIGNING_KEY_B64"):
            return JSONResponse(status_code=503, content={"detail": "Signing key is not configured"})
        # Count ASGI entries before selecting a credential; never select among duplicates.
        values = [
            value for name, value in request.scope["headers"]
            if name.lower() == b"x-api-key"
        ]
        supplied = values[0].decode("latin-1") if len(values) == 1 else ""
        durable_identity = None
        if supplied and credential_backend == "sqlite":
            try:
                from app.credentials import authenticate
                durable_identity = await run_in_threadpool(authenticate, supplied)
            except Exception:
                return JSONResponse(status_code=503, content={"detail": "Credential service unavailable"})
            valid_credential = durable_identity is not None
        else:
            valid_credential = supplied and credential_backend == "legacy" and any(
                hmac.compare_digest(supplied.encode("utf-8"), k.encode("utf-8")) for k in keys)
        if not valid_credential:
            return JSONResponse(status_code=401, content={"detail": "Invalid or missing API key"}, headers={"WWW-Authenticate": "ApiKey"})

        idempotency = None
        if idempotency_values:
            from app.idempotency import IdempotencyRequest, valid_key
            if (request.url.path != "/verify/signed" or request.method != "POST" or
                    len(idempotency_values) != 1 or not valid_key(idempotency_values[0])):
                return JSONResponse(status_code=400, content={"detail": "Invalid idempotency request"})
            if (os.getenv("AGENTVERIFY_IDEMPOTENCY_V390") != "1" or
                    credential_backend != "sqlite" or durable_identity is None):
                return JSONResponse(status_code=400, content={"detail": "Idempotency is unavailable for this request"})
            if (os.getenv("AGENTVERIFY_IDEMPOTENCY_SCHEMA_MANAGED") != "1" or
                    os.getenv("AGENTVERIFY_DURABLE_QUOTAS") != "1" or
                    os.getenv("AGENTVERIFY_CUSTOMER_TRACKING") != "1" or
                    os.getenv("AGENTVERIFY_USAGE_BACKEND") != "postgres"):
                return JSONResponse(status_code=503, content={"detail": "Idempotency service unavailable"})
            idempotency = IdempotencyRequest(
                tenant=durable_identity.developer_id,
                key=idempotency_values[0].decode("ascii"),
            )

        try:
            limit = int(os.getenv("AGENTVERIFY_RATE_LIMIT_PER_MINUTE", "60"))
            if not 1 <= limit <= 100000:
                raise ValueError()
        except ValueError:
            return JSONResponse(status_code=503, content={"detail": "Invalid rate limit configuration"})

        tracking = os.getenv("AGENTVERIFY_CUSTOMER_TRACKING", "0") == "1"
        quotas = os.getenv("AGENTVERIFY_DURABLE_QUOTAS", "0") == "1"
        if quotas and (not tracking or os.getenv("AGENTVERIFY_USAGE_BACKEND") != "postgres"):
            return JSONResponse(status_code=503, content={"detail": "Durable quotas require customer tracking and PostgreSQL"})

        cid = None
        if tracking:
            if durable_identity is not None:
                cid = durable_identity.developer_id
            else:
                try:
                    cid = customer_id(supplied)
                except ValueError:
                    return JSONResponse(status_code=503, content={"detail": "Customer tracking is not configured"})

        # Durable quota is reserved before the operation; errors fail closed.
        if quotas and idempotency is None:
            try:
                from app.quotas import consume
                allowed = await run_in_threadpool(consume, cid)
            except Exception:
                return JSONResponse(status_code=503, content={"detail": "Quota service unavailable"})
            if not allowed:
                return JSONResponse(status_code=429, content={"detail": "Daily request quota exceeded"}, headers={"Retry-After": "3600"})

        with _lock:
            now = time.monotonic()
            bucket = _hits[hashlib.sha256(supplied.encode()).digest()]
            while bucket and bucket[0] <= now - 60:
                bucket.popleft()
            if len(bucket) >= limit:
                return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"}, headers={"Retry-After": "60"})
            bucket.append(now)
        token = customer_context.set(cid) if tracking else None
        idempotency_token = idempotency_context.set(idempotency) if idempotency is not None else None
        try:
            return await call_next(request)
        finally:
            if idempotency_token is not None:
                idempotency_context.reset(idempotency_token)
            if token is not None:
                customer_context.reset(token)
