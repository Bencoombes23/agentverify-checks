"""Opt-in, PostgreSQL-backed atomic daily request quotas (UTC).

Schema-managed mode skips request-time DDL. Enable only after applying the
explicit quota migration to the same database. Default legacy behavior retained.
"""
import os
from datetime import datetime, timezone

from app.resilience import safe_close

def reserve(cur, customer: str, *, day=None, limit=None) -> bool:
    """Reserve within the caller's transaction; schema must already exist."""
    if not customer:
        raise ValueError("Customer identity required")
    if limit is None:
        limit = int(os.environ["AGENTVERIFY_DAILY_REQUEST_QUOTA"])
    if not 1 <= limit <= 10000000:
        raise ValueError("Daily quota must be between 1 and 10000000")
    day = day or datetime.now(timezone.utc).date()
    cur.execute("""INSERT INTO customer_daily_quotas (customer_id, day_utc, used)
        VALUES (%s, %s, 1)
        ON CONFLICT (customer_id, day_utc) DO UPDATE
            SET used = customer_daily_quotas.used + 1
            WHERE customer_daily_quotas.used < %s
        RETURNING used""", (customer, day, limit))
    return cur.fetchone() is not None

def consume(customer: str) -> bool:
    """Reserve one request. True=allowed, False=exhausted. Errors propagate (fail closed)."""
    from app.usage import _postgres_connection
    if not customer:
        raise ValueError("Customer identity required")
    from app.startup import runtime_environment
    env = runtime_environment()
    limit = int(env["AGENTVERIFY_DAILY_REQUEST_QUOTA"])
    if not 1 <= limit <= 10000000:
        raise ValueError("Daily quota must be between 1 and 10000000")
    day = datetime.now(timezone.utc).date()
    # A driver commit exception may escape __exit__ before it closes the connection.
    db = _postgres_connection()
    try:
        with db:
            with db.cursor() as cur:
                if (env.get("AGENTVERIFY_QUOTA_SCHEMA_MANAGED") != "1" and
                        env.get("AGENTVERIFY_POSTGRES_SCHEMA_MANAGED") != "1"):
                    cur.execute("""CREATE TABLE IF NOT EXISTS customer_daily_quotas (
                    customer_id TEXT NOT NULL,
                    day_utc DATE NOT NULL,
                    used BIGINT NOT NULL CHECK (used >= 0),
                    PRIMARY KEY (customer_id, day_utc)
                )""")
                return reserve(cur, customer, day=day, limit=limit)
    finally:
        safe_close(db)
