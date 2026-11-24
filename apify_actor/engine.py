"""Pure check logic for the Apify Actor wrapper. No Apify SDK import, so it is unit-testable.

Reuses the AgentVerify engine unchanged: app.models.VerificationRequest, app.verifier.verify
and app.receipts.issue_receipt. One input item in, one output item out.
"""
from __future__ import annotations

import json
from typing import Any

from pydantic import ValidationError

from app.models import VerificationRequest
from app.verifier import verify

# Event names; prices are set in Apify Console (see ACTOR_PUBLISHING.md).
EVENT_VERIFICATION = "verification"
EVENT_SIGNED_RECEIPT = "signed-receipt"

MAX_CHECKS_PER_RUN = 1000


def process_check(index: int, raw: Any, sign: bool) -> tuple[dict[str, Any], list[str]]:
    """Run one check. Returns (output_item, billable_event_names).

    A well-formed request that passes OR fails is a real result and is billable.
    A malformed request or a business-rule rejection (HTTP 422 in the web API) is returned
    as an error item and is NOT billable.
    """
    if not isinstance(raw, dict):
        return _error(index, "invalid_request", "Each check must be a JSON object"), []
    try:
        parsed = VerificationRequest.model_validate(raw)
        result = verify(parsed)
    except ValidationError as exc:
        details = json.loads(exc.json(include_url=False, include_input=False, include_context=False))
        return _error(index, "invalid_request", details), []
    except Exception as exc:  # verifier raises fastapi.HTTPException for business-rule errors
        if hasattr(exc, "status_code") and hasattr(exc, "detail"):
            return _error(index, "verification_error", exc.detail), []
        raise

    item: dict[str, Any] = {"index": index}
    item.update(result.model_dump(mode="json", exclude_none=True))
    events = [EVENT_VERIFICATION]
    if sign:
        from app.receipts import issue_receipt  # imported lazily: needs the signing key env var
        item["receipt"] = issue_receipt(parsed, result)
        events.append(EVENT_SIGNED_RECEIPT)
    return item, events


def _error(index: int, code: str, details: Any) -> dict[str, Any]:
    return {"index": index, "status": "error", "error": code, "details": details}
