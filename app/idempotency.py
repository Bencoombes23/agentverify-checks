"""Opt-in PostgreSQL idempotency for durable-credential signed verification."""
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import json
import secrets

from app.resilience import diagnostic, safe_close, safe_rollback

ROUTE = "/verify/signed"
CONTRACT = "agentverify-idempotency-v1"


class Conflict(Exception):
    pass


class InProgress(Exception):
    pass


class Unavailable(Exception):
    pass


class QuotaExceeded(Exception):
    pass


@dataclass(frozen=True)
class IdempotencyRequest:
    tenant: str
    key: str


def valid_key(value: bytes) -> bool:
    return (16 <= len(value) <= 128 and b"," not in value and
            all(0x20 <= byte <= 0x7e for byte in value))


def fingerprint(request) -> str:
    canonical = json.dumps({
        "contract": CONTRACT,
        "route": ROUTE,
        "request": _canonical_value(request.model_dump(mode="python", exclude_none=True)),
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


def _canonical_value(value):
    if isinstance(value, Decimal):
        if value == 0:
            return "0"
        return format(value.normalize(), "f")
    if isinstance(value, dict):
        return {key: _canonical_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canonical_value(item) for item in value]
    return value


def _row(cur, identity, *, lock=False):
    suffix = " FOR UPDATE" if lock else ""
    cur.execute("""SELECT request_fingerprint, state, response_status,
                          response_body, response_sha256, updated_at, owner_token
                   FROM verification_idempotency
                   WHERE tenant_id=%s AND route=%s AND idempotency_key=%s""" + suffix,
                (identity.tenant, ROUTE, identity.key))
    return cur.fetchone()


def _committed(row, expected):
    if row[0] != expected:
        raise Conflict()
    if row[1] == "in_progress":
        updated = row[5]
        if updated is not None and updated.tzinfo is None:
            updated = updated.replace(tzinfo=timezone.utc)
        if updated is not None and (datetime.now(timezone.utc) - updated).total_seconds() <= 60:
            raise InProgress()
        raise Unavailable()
    if row[1] != "committed" or row[2] != 200 or row[3] is None or row[4] is None:
        raise Unavailable()
    body = row[3]
    if hashlib.sha256(body.encode("utf-8")).hexdigest() != row[4]:
        raise Unavailable()
    try:
        parsed = json.loads(body)
    except (TypeError, ValueError):
        raise Unavailable() from None
    return parsed, body


def _timeouts(cur):
    cur.execute("SET LOCAL lock_timeout = '2s'")
    cur.execute("SET LOCAL statement_timeout = '5s'")
    cur.execute("SET LOCAL idle_in_transaction_session_timeout = '10s'")


def _existing(row, expected):
    if row[0] != expected:
        raise Conflict()
    if row[1] == "committed":
        return _committed(row, expected)
    if row[1] == "in_progress":
        return _committed(row, expected)  # Raises bounded 425 or fail-closed 503.
    raise Unavailable()


def _reconcile_claim(identity, expected, token):
    from app.usage import _postgres_connection
    db = None
    try:
        db = _postgres_connection()
        with db.cursor() as cur:
            row = _row(cur, identity)
            if row is None:
                raise Unavailable()
            if row[0] != expected:
                raise Conflict()
            if row[1] == "committed":
                return None, _committed(row, expected)
            if row[1] == "in_progress" and row[6] == token:
                return token, None
            _existing(row, expected)
    except (Conflict, InProgress, Unavailable):
        raise
    except Exception:
        raise Unavailable() from None
    finally:
        if db is not None:
            safe_close(db)


def _claim(identity, expected):
    """Commit ownership before execution; return (token, replay-or-None)."""
    from app.usage import _postgres_connection
    token = secrets.token_hex(32)
    db = None
    commit_started = False
    try:
        db = _postgres_connection()
        with db.cursor() as cur:
            _timeouts(cur)
            cur.execute("""INSERT INTO verification_idempotency
                (tenant_id, route, idempotency_key, request_fingerprint, state,
                 owner_token, created_at, updated_at, retain_until)
                VALUES (%s,%s,%s,%s,'in_progress',%s,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,
                        CURRENT_TIMESTAMP + INTERVAL '30 days')
                ON CONFLICT DO NOTHING RETURNING 1""",
                (identity.tenant, ROUTE, identity.key, expected, token))
            owner = cur.fetchone() is not None
            if not owner:
                return None, _existing(_row(cur, identity), expected)
        commit_started = True
        db.commit()
        return token, None
    except (Conflict, InProgress, Unavailable):
        raise
    except Exception as exc:
        if not commit_started:
            raise Unavailable() from None
        diagnostic("transaction_outcome_uncertain", exc)
    finally:
        if db is not None:
            safe_close(db)
    return _reconcile_claim(identity, expected, token)


def _block_claim(identity, expected, token):
    """Best effort only: the committed in_progress claim is already a fence."""
    from app.usage import _postgres_connection
    db = None
    try:
        db = _postgres_connection()
        with db.cursor() as cur:
            _timeouts(cur)
            cur.execute("""UPDATE verification_idempotency SET state='blocked',
                updated_at=CURRENT_TIMESTAMP
                WHERE tenant_id=%s AND route=%s AND idempotency_key=%s
                  AND request_fingerprint=%s AND state='in_progress'
                  AND owner_token=%s""",
                (identity.tenant, ROUTE, identity.key, expected, token))
        db.commit()
    except Exception as exc:
        diagnostic("idempotency_block_failed", exc)
    finally:
        if db is not None:
            safe_close(db)


def _reconcile_operation(identity, expected):
    from app.usage import _postgres_connection
    db = None
    try:
        db = _postgres_connection()
        with db.cursor() as cur:
            row = _row(cur, identity)
            if row is None:
                raise Unavailable()
            if row[1] == "committed":
                return _committed(row, expected)
            # The original caller receives 503 unless commit is positively
            # confirmed. The durable claim remains the fence for later 425s.
            raise Unavailable()
    except (Conflict, Unavailable):
        raise
    except Exception as exc:
        diagnostic("idempotency_reconcile_failed", exc)
        raise Unavailable() from None
    finally:
        if db is not None:
            safe_close(db)


def execute(identity, request, produce):
    """Return (parsed response, exact UTF-8 body, replayed)."""
    from app.quotas import reserve
    from app.usage import _postgres_connection
    expected = fingerprint(request)
    token, replay = _claim(identity, expected)
    if replay is not None:
        return (*replay, True)
    db = None; commit_started = False
    producer_started = False
    producer_complete = False
    try:
        db = _postgres_connection()
        with db.cursor() as cur:
            _timeouts(cur)
            row = _row(cur, identity, lock=True)
            if (row is None or row[0] != expected or row[1] != "in_progress" or
                    row[6] != token):
                raise Unavailable()
            if not reserve(cur, identity.tenant):
                raise QuotaExceeded()
            producer_started = True
            response = produce()
            producer_complete = True
            body = json.dumps(response, separators=(",", ":"), ensure_ascii=False)
            digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
            cur.execute("""UPDATE verification_idempotency
                SET state='committed', response_status=200, response_body=%s,
                    response_sha256=%s, updated_at=CURRENT_TIMESTAMP
                WHERE tenant_id=%s AND route=%s AND idempotency_key=%s
                  AND state='in_progress' AND request_fingerprint=%s
                  AND owner_token=%s""",
                (body, digest, identity.tenant, ROUTE, identity.key, expected, token))
            if cur.rowcount != 1:
                raise Unavailable()
        commit_started = True
        db.commit()
        return response, body, False
    except (Conflict, InProgress, Unavailable, QuotaExceeded):
        if db is not None and not commit_started:
            safe_rollback(db)
        _block_claim(identity, expected, token)
        raise
    except Exception as exc:
        if not commit_started:
            if db is not None:
                safe_rollback(db)
            if producer_started and not producer_complete:
                _block_claim(identity, expected, token)
                raise
            _block_claim(identity, expected, token)
            raise Unavailable() from None
        diagnostic("transaction_outcome_uncertain", exc)
    finally:
        if db is not None:
            safe_close(db)
    return _reconcile_operation(identity, expected) + (True,)


def execute_signed(identity, request, produce):
    try:
        parsed, body, replayed = execute(identity, request, produce)
        return parsed, body, replayed
    except Conflict:
        raise _http(409, "Idempotency key conflicts with another request")
    except InProgress:
        raise _http(425, "Operation is still in progress", {"Retry-After": "2"})
    except QuotaExceeded:
        raise _http(429, "Daily request quota exceeded", {"Retry-After": "3600"})
    except Unavailable:
        raise _http(503, "Idempotency service unavailable")


def _http(status, detail, headers=None):
    from fastapi import HTTPException
    return HTTPException(status_code=status, detail=detail, headers=headers)


def migrate():
    """Apply the explicit consolidated migration; request handling never runs DDL."""
    from app.schema_contract import apply_migration
    apply_migration()
