"""Unified immutable startup configuration and durable dependency gate."""
from __future__ import annotations

from contextlib import asynccontextmanager, closing
from dataclasses import dataclass, field
import hashlib
import json
import os
import threading
from types import MappingProxyType
from typing import Mapping


class StartupValidationError(RuntimeError):
    """Safe startup failure without secret-bearing details."""


_MARKERS = ("RENDER", "RENDER_SERVICE_ID", "DYNO", "K_SERVICE",
            "WEBSITE_INSTANCE_ID", "AWS_LAMBDA_FUNCTION_NAME",
            "FORWARDED_ALLOW_IPS", "UVICORN_FORWARDED_ALLOW_IPS")


def _relevant(env: Mapping[str, str]) -> dict[str, str]:
    return {key: value for key, value in env.items()
            if key.startswith("AGENTVERIFY_") or key in _MARKERS}


def _digest(env: Mapping[str, str]) -> str:
    payload = json.dumps(_relevant(env), sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class StartupConfig:
    public: bool
    cloud: bool
    hosted: bool
    credential_backend: str
    usage_backend: str
    durable_quotas: bool
    idempotency: bool
    customer_tracking: bool
    postgres_schema_managed: bool
    postgres_schema: str
    environment_digest: str
    environment: Mapping[str, str] = field(repr=False, compare=False)

    @property
    def postgres_required(self) -> bool:
        return (self.usage_backend == "postgres" or self.durable_quotas or self.idempotency)

    @property
    def strict(self) -> bool:
        return self.public or self.cloud or self.hosted or self.durable_quotas or self.idempotency


@dataclass(frozen=True)
class StartupState:
    config: StartupConfig
    ready: bool
    owner: object | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True)
class DependencyHealth:
    available: bool
    consecutive_failures: int
    owner: object | None = field(default=None, repr=False, compare=False)


_state: StartupState | None = None
_health: DependencyHealth | None = None
_owner: object | None = None
_owner_lock = threading.Lock()


def build_config(env: Mapping[str, str] | None = None) -> StartupConfig:
    source = dict(os.environ if env is None else env)
    from app.credentials import backend_name
    from app.deployment_config import deployment_errors
    errors = deployment_errors(source, include_startup=False)
    if errors:
        raise StartupValidationError("Deployment configuration invalid")
    usage = source.get("AGENTVERIFY_USAGE_BACKEND", "sqlite").lower()
    if usage not in {"sqlite", "postgres"}:
        raise StartupValidationError("Usage backend invalid")
    durable = source.get("AGENTVERIFY_DURABLE_QUOTAS") == "1"
    idem = source.get("AGENTVERIFY_IDEMPOTENCY_V390") == "1"
    tracking = source.get("AGENTVERIFY_CUSTOMER_TRACKING") == "1"
    hosted = any(source.get(key) for key in _MARKERS[:6])
    managed = (source.get("AGENTVERIFY_POSTGRES_SCHEMA_MANAGED") == "1" or
               (durable and source.get("AGENTVERIFY_QUOTA_SCHEMA_MANAGED") == "1") or
               (idem and source.get("AGENTVERIFY_IDEMPOTENCY_SCHEMA_MANAGED") == "1"))
    schema = source.get("AGENTVERIFY_POSTGRES_SCHEMA", "public")
    strict = (source.get("AGENTVERIFY_PUBLIC_MODE") == "1" or
              source.get("AGENTVERIFY_CLOUD_MODE") == "1" or hosted or durable or idem)
    postgres_required = usage == "postgres" or durable or idem
    if postgres_required and strict and not managed:
        raise StartupValidationError("Managed PostgreSQL schema required")
    if schema != "public":
        raise StartupValidationError("PostgreSQL schema invalid")
    frozen = MappingProxyType(source)
    return StartupConfig(
        public=source.get("AGENTVERIFY_PUBLIC_MODE") == "1",
        cloud=source.get("AGENTVERIFY_CLOUD_MODE") == "1", hosted=hosted,
        credential_backend=backend_name(source), usage_backend=usage,
        durable_quotas=durable, idempotency=idem, customer_tracking=tracking,
        postgres_schema_managed=managed, postgres_schema=schema,
        environment_digest=_digest(source), environment=frozen,
    )


def validate_dependencies(config: StartupConfig) -> None:
    if config.credential_backend == "sqlite":
        from app.credentials import healthcheck
        healthcheck(env=config.environment)
    if config.postgres_required:
        from app.schema_contract import validate_postgres
        from app.usage import _postgres_connection
        with closing(_postgres_connection(env=config.environment)) as db:
            with db.cursor() as cur:
                cur.execute("SET LOCAL lock_timeout = '2s'")
                cur.execute("SET LOCAL statement_timeout = '5s'")
                cur.execute("SET LOCAL idle_in_transaction_session_timeout = '10s'")
            validate_postgres(db, schema=config.postgres_schema)


def _record_health(owner: object, available: bool) -> None:
    global _health
    transition = None
    with _owner_lock:
        if _owner is not owner or _state is None or _state.owner is not owner:
            return
        prior = _health if _health is not None and _health.owner is owner else None
        failures = 0 if available else (
            1 if prior is None else prior.consecutive_failures + 1)
        _health = DependencyHealth(available, failures, owner)
        if prior is not None and prior.available != available:
            transition = "dependency_recovered" if available else "dependency_degraded"
    if transition is not None:
        from app.resilience import diagnostic
        diagnostic(transition)


def probe_dependencies(config: StartupConfig, *, owner: object | None = None) -> bool:
    try:
        validate_dependencies(config)
        if owner is not None:
            _record_health(owner, True)
        return True
    except Exception as exc:
        if owner is not None:
            _record_health(owner, False)
        from app.resilience import diagnostic
        diagnostic("dependency_probe_failed", exc)
        return False


def current_state() -> StartupState | None:
    with _owner_lock:
        return _state


def dependency_health() -> DependencyHealth | None:
    with _owner_lock:
        return _health


def runtime_environment() -> Mapping[str, str]:
    state = current_state()
    return state.config.environment if state and state.ready else os.environ


def environment_changed(env: Mapping[str, str] | None = None) -> bool:
    state = current_state()
    return bool(state and state.ready and
                _digest(os.environ if env is None else env) != state.config.environment_digest)


@asynccontextmanager
async def application_lifespan(_application):
    global _health, _owner, _state
    token = object()
    with _owner_lock:
        if _owner is not None or _state is not None:
            raise StartupValidationError("Startup state already initialized")
        _owner = token
    try:
        config = build_config()
        try:
            validate_dependencies(config)
        except StartupValidationError:
            raise
        except Exception as exc:
            raise StartupValidationError("Durable dependency validation failed") from exc
        with _owner_lock:
            if _owner is not token or _state is not None:
                raise StartupValidationError("Startup ownership invalid")
            _state = StartupState(config=config, ready=True, owner=token)
            _health = DependencyHealth(True, 0, token)
        yield
    finally:
        with _owner_lock:
            if _owner is token and (_state is None or _state.owner is token):
                _state = None
                _health = None
                _owner = None
