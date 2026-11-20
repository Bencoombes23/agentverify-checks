"""MCP stdio adapter for AgentVerify's existing deterministic engine.

Run via: python -m app.mcp_server
MCP clients launch this as a subprocess and communicate over stdin/stdout.
"""
from typing import Any

from mcp.server.fastmcp import FastMCP
from pydantic import ValidationError

from app.models import BatchRequest, VerificationRequest
from app.receipts import check_receipt, issue_receipt, public_key_info
from app.verifier import verify
from app.usage import record

mcp = FastMCP("AgentVerify")


def _error(exc: Exception) -> dict[str, Any]:
    """Return predictable tool errors without printing to MCP stdout."""
    if isinstance(exc, ValidationError):
        return {"error": "invalid_request", "details": exc.errors(include_url=False, include_input=False)}
    # Existing verifier raises HTTPException for business-rule errors.
    if hasattr(exc, "status_code") and hasattr(exc, "detail"):
        return {"error": "verification_error", "status_code": exc.status_code, "details": exc.detail}
    raise exc


def calculate(request: dict[str, Any]) -> dict[str, Any]:
    try:
        parsed = VerificationRequest.model_validate(request)
        result = verify(parsed)
        record("mcp", "verify", int(result.status == "passed"), int(result.status == "failed"))
        return result.model_dump(mode="json", exclude_none=True)
    except (ValidationError, Exception) as exc:
        return _error(exc)


def calculate_batch(requests: list[dict[str, Any]]) -> dict[str, Any]:
    try:
        parsed = BatchRequest.model_validate({"requests": requests})
        results = [verify(item) for item in parsed.requests]
        passed = sum(item.status == "passed" for item in results)
        record("mcp", "batch", passed, len(results) - passed)
        return {
            "total": len(results), "passed": passed, "failed": len(results) - passed,
            "results": [item.model_dump(mode="json", exclude_none=True) for item in results],
        }
    except (ValidationError, Exception) as exc:
        return _error(exc)


def calculate_signed(request: dict[str, Any]) -> dict[str, Any]:
    try:
        parsed = VerificationRequest.model_validate(request)
        result = verify(parsed)
        receipt = issue_receipt(parsed, result)
        record("mcp", "signed", int(result.status == "passed"), int(result.status == "failed"))
        return receipt
    except (ValidationError, Exception) as exc:
        return _error(exc)


@mcp.tool()
def verify_calculation(request: dict[str, Any]) -> dict[str, Any]:
    """Check a claimed numerical result. Request fields: calculation_type, claimed_result, inputs, optional tolerance. Returns passed/failed and independently calculated result. Claim-vs-source categories (quote_in_text, number_in_text, date_in_text) take source_text you supply plus claim_text (or claimed_result for numbers); they prove only that the supplied text contains the claim, not that it is true."""
    return calculate(request)


@mcp.tool()
def verify_batch(requests: list[dict[str, Any]]) -> dict[str, Any]:
    """Check up to 50 numerical claims in one call. Each item has calculation_type, claimed_result, inputs and optional tolerance."""
    return calculate_batch(requests)


@mcp.tool()
def verify_and_sign(request: dict[str, Any]) -> dict[str, Any]:
    """Check a numerical claim and issue a locally signed Ed25519 receipt. The signature proves integrity and local issuer identity, not the truth of supplied inputs."""
    return calculate_signed(request)


@mcp.tool()
def check_signed_receipt(receipt: dict[str, Any]) -> dict[str, bool]:
    """Check whether an AgentVerify receipt has an intact signature from this local issuer."""
    return {"valid": check_receipt(receipt)}


@mcp.tool()
def get_public_key() -> dict[str, str]:
    """Return the public signing key for this AgentVerify instance."""
    return public_key_info()


if __name__ == "__main__":
    mcp.run(transport="stdio")

