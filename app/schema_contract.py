"""Versioned, read-only PostgreSQL schema validation and explicit migration."""
from __future__ import annotations

from contextlib import closing
from pathlib import Path


SCHEMA_VERSION = "4.00-stage2-1"
SCHEMA_NAME = "public"
MIGRATION = Path(__file__).resolve().parents[1] / "migrations" / "v400_stage2_postgres.sql"


class SchemaContractError(RuntimeError):
    """Low-cardinality schema failure; never contains SQL or connection details."""


EXPECTED_COLUMNS = {
    "agentverify_schema": {
        "singleton": ("bool", "NO"), "version": ("text", "NO"),
    },
    "usage_events": {
        "id": ("int8", "NO"), "timestamp_utc": ("timestamptz", "NO"),
        "source": ("text", "NO"), "operation": ("text", "NO"),
        "passed": ("int4", "NO"), "failed": ("int4", "NO"),
        "customer_id": ("text", "YES"),
    },
    "customer_daily_quotas": {
        "customer_id": ("text", "NO"), "day_utc": ("date", "NO"),
        "used": ("int8", "NO"),
    },
    "verification_idempotency": {
        "tenant_id": ("text", "NO"), "route": ("text", "NO"),
        "idempotency_key": ("text", "NO"), "request_fingerprint": ("bpchar", "NO"),
        "state": ("text", "NO"), "owner_token": ("bpchar", "NO"),
        "response_status": ("int2", "YES"), "response_body": ("text", "YES"),
        "response_sha256": ("bpchar", "YES"), "created_at": ("timestamptz", "NO"),
        "updated_at": ("timestamptz", "NO"), "retain_until": ("timestamptz", "NO"),
    },
}

EXPECTED_PRIMARY_KEYS = {
    "agentverify_schema": ("singleton",),
    "usage_events": ("id",),
    "customer_daily_quotas": ("customer_id", "day_utc"),
    "verification_idempotency": ("tenant_id", "route", "idempotency_key"),
}

EXPECTED_CHECKS = {
    "agentverify_schema": {
        "agentverify_schema_singleton_check": "CHECK (singleton)",
    },
    "usage_events": {},
    "customer_daily_quotas": {
        "customer_daily_quotas_used_check": "CHECK (used >= 0)",
    },
    "verification_idempotency": {
        "verification_idempotency_state_check": (
            "CHECK (state = ANY (ARRAY['in_progress'::text, 'committed'::text, "
            "'blocked'::text]))"
        ),
        "verification_idempotency_check": (
            "CHECK ((state = 'committed'::text) = (response_status IS NOT NULL AND "
            "response_body IS NOT NULL AND response_sha256 IS NOT NULL))"
        ),
    },
}


def _constraint_definition(value: str) -> str:
    """Collapse whitespace outside SQL quotes without altering quoted content."""
    if not isinstance(value, str):
        raise SchemaContractError("PostgreSQL check contract mismatch")
    result = []
    quote = None
    pending_space = False
    index = 0
    while index < len(value):
        character = value[index]
        if quote is not None:
            result.append(character)
            if character == quote:
                if index + 1 < len(value) and value[index + 1] == quote:
                    result.append(value[index + 1])
                    index += 1
                else:
                    quote = None
        elif character in {"'", '"'}:
            if pending_space and result:
                result.append(" ")
            pending_space = False
            quote = character
            result.append(character)
        elif character.isspace():
            pending_space = True
        else:
            if pending_space and result:
                result.append(" ")
            pending_space = False
            result.append(character)
        index += 1
    if quote is not None:
        raise SchemaContractError("PostgreSQL check contract mismatch")
    return "".join(result)


def _schema_name(value: str) -> str:
    if value != SCHEMA_NAME:
        raise SchemaContractError("Unsupported PostgreSQL schema")
    return value


def validate_postgres(db, *, schema: str = SCHEMA_NAME) -> None:
    """Validate the complete contract without DDL or transaction commits."""
    schema = _schema_name(schema)
    try:
        with db.cursor() as cur:
            cur.execute("SET LOCAL statement_timeout = '5s'")
            cur.execute("SET LOCAL lock_timeout = '2s'")
            cur.execute("""SELECT table_name, column_name, udt_name, is_nullable
                FROM information_schema.columns
                WHERE table_schema=%s AND table_name = ANY(%s)
                ORDER BY table_name, ordinal_position""",
                (schema, list(EXPECTED_COLUMNS)))
            actual = {name: {} for name in EXPECTED_COLUMNS}
            for table, column, data_type, nullable in cur.fetchall():
                if table in actual:
                    actual[table][column] = (data_type, nullable)
            if actual != EXPECTED_COLUMNS:
                raise SchemaContractError("PostgreSQL column contract mismatch")

            cur.execute("""SELECT tc.table_name, kcu.column_name, kcu.ordinal_position
                FROM information_schema.table_constraints tc
                JOIN information_schema.key_column_usage kcu
                  ON tc.constraint_catalog=kcu.constraint_catalog
                 AND tc.constraint_schema=kcu.constraint_schema
                 AND tc.constraint_name=kcu.constraint_name
                WHERE tc.table_schema=%s AND tc.constraint_type='PRIMARY KEY'
                  AND tc.table_name = ANY(%s)
                ORDER BY tc.table_name, kcu.ordinal_position""",
                (schema, list(EXPECTED_PRIMARY_KEYS)))
            keys = {name: [] for name in EXPECTED_PRIMARY_KEYS}
            for table, column, _ordinal in cur.fetchall():
                if table in keys:
                    keys[table].append(column)
            if {k: tuple(v) for k, v in keys.items()} != EXPECTED_PRIMARY_KEYS:
                raise SchemaContractError("PostgreSQL key contract mismatch")

            cur.execute("SELECT version FROM public.agentverify_schema WHERE singleton=TRUE")
            if cur.fetchall() != [(SCHEMA_VERSION,)]:
                raise SchemaContractError("PostgreSQL schema version mismatch")

            cur.execute("""SELECT indexdef FROM pg_indexes
                WHERE schemaname=%s AND tablename='usage_events'
                  AND indexname='usage_events_customer_id_idx'""", (schema,))
            rows = cur.fetchall()
            if len(rows) != 1 or "(customer_id)" not in rows[0][0].replace('"', ''):
                raise SchemaContractError("PostgreSQL index contract mismatch")

            cur.execute("""SELECT c.relname, x.conname, pg_get_constraintdef(x.oid, TRUE)
                FROM pg_constraint x JOIN pg_class c ON c.oid=x.conrelid
                JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname=%s AND c.relname = ANY(%s) AND x.contype='c'""",
                (schema, list(EXPECTED_CHECKS)))
            actual_checks = {name: {} for name in EXPECTED_CHECKS}
            for table, name, definition in cur.fetchall():
                if table not in actual_checks or name in actual_checks[table]:
                    raise SchemaContractError("PostgreSQL check contract mismatch")
                actual_checks[table][name] = _constraint_definition(definition)
            expected_checks = {
                table: {name: _constraint_definition(definition)
                        for name, definition in definitions.items()}
                for table, definitions in EXPECTED_CHECKS.items()
            }
            if actual_checks != expected_checks:
                raise SchemaContractError("PostgreSQL check contract mismatch")
    except SchemaContractError:
        raise
    except Exception as exc:
        raise SchemaContractError("PostgreSQL schema validation unavailable") from exc


def apply_migration() -> None:
    """Explicit operator action. Application startup never calls this function."""
    from app.usage import _postgres_connection
    try:
        sql = MIGRATION.read_text(encoding="utf-8", errors="strict")
        with closing(_postgres_connection()) as db:
            with db.cursor() as cur:
                cur.execute(sql)
            validate_postgres(db)
            db.commit()
    except SchemaContractError:
        raise
    except Exception as exc:
        raise SchemaContractError("PostgreSQL migration failed") from exc
