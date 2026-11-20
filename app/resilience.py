"""Bounded operational diagnostics and exception-safe resource cleanup."""
from __future__ import annotations

import logging
import threading
import time


logger = logging.getLogger("agentverify.operations")

_EVENTS = frozenset({
    "database_close_failed",
    "database_rollback_failed",
    "connection_acquisition_failed",
    "dependency_degraded",
    "dependency_probe_failed",
    "dependency_recovered",
    "idempotency_block_failed",
    "idempotency_reconcile_failed",
    "usage_record_failed",
    "transaction_outcome_uncertain",
})
_DIAGNOSTIC_INTERVAL_SECONDS = 60.0
_diagnostic_lock = threading.Lock()
_last_diagnostic: dict[str, float] = {}


def diagnostic(event: str, failure: BaseException | None = None) -> None:
    """Emit a rate-bounded event code and exception class, never exception text."""
    if event not in _EVENTS:
        raise ValueError("Unsupported operational event")
    failure_name = "none" if failure is None else type(failure).__name__
    now = time.monotonic()
    with _diagnostic_lock:
        previous = _last_diagnostic.get(event)
        if previous is not None and now - previous < _DIAGNOSTIC_INTERVAL_SECONDS:
            return
        _last_diagnostic[event] = now
    logger.warning("operational_event=%s failure_type=%s", event, failure_name)


def _reset_diagnostics_for_tests() -> None:
    """Clear throttle state for deterministic isolated regression tests."""
    with _diagnostic_lock:
        _last_diagnostic.clear()


def safe_rollback(db) -> bool:
    """Best-effort rollback that cannot replace the original failure."""
    try:
        db.rollback()
        return True
    except Exception as exc:
        diagnostic("database_rollback_failed", exc)
        return False


def safe_close(db) -> bool:
    """Close a resource without masking a transaction or application result."""
    try:
        db.close()
        return True
    except Exception as exc:
        diagnostic("database_close_failed", exc)
        return False
