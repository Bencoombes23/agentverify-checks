"""AgentVerify v0.5. Free by default; payment preview is development-only."""
import os
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Request, Response

from app import __version__
from app.models import BatchRequest, BatchResponse, VerificationRequest, VerificationResponse
from app.receipts import check_receipt, issue_receipt, public_key_info
from app.usage import record
from app.verifier import verify
from app.startup import application_lifespan

app = FastAPI(
    title="AgentVerify",
    description="Deterministic verification for AI agents. Free during development.",
    version=__version__,
    lifespan=application_lifespan,
)

@app.get("/health")
def health():
    return {"status": "healthy", "service": "AgentVerify", "version": __version__}

@app.get("/pricing")
def pricing():
    from app.x402_gate import pricing_info
    x402 = pricing_info()
    if x402 is not None:  # AV-017: only when x402 is enabled and valid
        return {"mode": "api-key-or-x402", "currency": "USD", "payment_required": False,
                "x402_enabled": True, "x402": x402,
                "note": "Experimental. API-key callers are unaffected; x402 is an alternative."}
    return {
        "mode": "free",
        "currency": "USD",
        "price_per_verification": "0",
        "payment_required": False,
        "x402_enabled": False,
        "note": "All verification endpoints are free. No real payments are accepted.",
    }

@app.get("/ready", include_in_schema=False)
def readiness(request: Request):
    """Opt-in operator readiness. Disabled deployments retain a generic 404."""
    from app.readiness import check_operator_header, dependency_check, enabled
    if not enabled():
        raise HTTPException(status_code=404, detail="Not found")
    if not check_operator_header(request.scope):
        raise HTTPException(status_code=401, detail="Invalid readiness credential")
    if not dependency_check():
        raise HTTPException(status_code=503, detail="Service not ready")
    return {"status": "ready"}

@app.post("/verify", response_model=VerificationResponse)
def verify_calculation(request: VerificationRequest):
    result = verify(request)
    record("http", "verify", int(result.status == "passed"), int(result.status == "failed"))
    return result

@app.post("/verify/batch", response_model=BatchResponse)
def verify_batch(request: BatchRequest):
    results = [verify(item) for item in request.requests]
    passed = sum(item.status == "passed" for item in results)
    record("http", "batch", passed, len(results) - passed)
    return BatchResponse(total=len(results), passed=passed, failed=len(results) - passed, results=results)

@app.get("/receipts/public-key")
def receipt_public_key():
    return public_key_info()

@app.post("/verify/signed")
def verify_signed(request: VerificationRequest):
    from app.security import idempotency_context
    idempotency = idempotency_context.get()
    if idempotency is not None:
        from app.idempotency import execute_signed
        body, exact_body, replayed = execute_signed(
            idempotency, request,
            lambda: issue_receipt(request, verify(request)),
        )
        if not replayed:
            result = body["payload"]["result"]
            record("http", "signed", int(result["status"] == "passed"),
                   int(result["status"] == "failed"))
        return Response(content=exact_body, status_code=200, media_type="application/json")
    result = verify(request)
    receipt = issue_receipt(request, result)
    record("http", "signed", int(result.status == "passed"), int(result.status == "failed"))
    return receipt

@app.post("/receipts/check")
def verify_receipt(receipt: dict[str, Any] = Body(...)):
    return {"valid": check_receipt(receipt)}

@app.get("/payments/preview")
def payment_preview():
    """Opt-in demo of a 402 status, NOT an x402 implementation or payment gate."""
    if os.environ.get("AGENTVERIFY_DEV_PAYMENT_PREVIEW") != "1":
        raise HTTPException(status_code=404, detail="Development preview disabled")
    raise HTTPException(status_code=402, detail={
        "simulation": True,
        "payment_accepted": False,
        "message": "Illustrative HTTP 402 only. No payment is requested or processed.",
    })

from app.security import APIProtectionMiddleware
app.add_middleware(APIProtectionMiddleware)
# AV-017: optional x402 pay-per-call gate (inert unless AGENTVERIFY_X402_ENABLED=1).
# Outside APIProtection so a verified payment can mark the request, inside the body cap.
from app.x402_gate import X402GateMiddleware
app.add_middleware(X402GateMiddleware)
# AV-013 (F02): added last so the body cap is the outermost layer.
from app.body_limit import BodySizeLimitMiddleware
app.add_middleware(BodySizeLimitMiddleware)

# AgentVerify V0.8 remote MCP (opt-in). Local stdio MCP remains unchanged.
# Mounting at / means the SDK's default /mcp route is reachable at /mcp.
# This mount is last so existing FastAPI routes keep priority.
if os.getenv("AGENTVERIFY_REMOTE_MCP", "0") == "1":
    if os.getenv("AGENTVERIFY_PUBLIC_MODE") != "1":
        raise RuntimeError("Remote MCP requires AGENTVERIFY_PUBLIC_MODE=1")
    from contextlib import asynccontextmanager
    from app.mcp_server import mcp

    if not hasattr(mcp, "streamable_http_app"):
        raise RuntimeError("Installed MCP SDK lacks Streamable HTTP; install requirements")

    from mcp.server.transport_security import TransportSecuritySettings

    mcp.settings.stateless_http = True
    from app.mcp_hosts import allowed_hosts_and_origins
    _mcp_hosts, _mcp_origins = allowed_hosts_and_origins()
    mcp.settings.transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=_mcp_hosts,
        allowed_origins=_mcp_origins,
    )

    remote_mcp_app = mcp.streamable_http_app()
    previous_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def agentverify_mcp_lifespan(application):
        async with previous_lifespan(application):
            async with mcp.session_manager.run():
                yield

    app.router.lifespan_context = agentverify_mcp_lifespan
    app.mount("/", remote_mcp_app)

# Documentation changes do not add a second authentication implementation.
from app.api_docs import configure_openapi
configure_openapi(app)
from app.error_responses import configure_error_responses
configure_error_responses(app)
