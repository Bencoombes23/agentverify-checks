"""Research-only guarded Uvicorn entrypoint for AgentVerify.

This protects launches USING this entrypoint. Direct uvicorn invocations bypass
this launch guard and must be separately controlled at deployment level.
"""
from __future__ import annotations

import argparse
import ipaddress
import os
import sys
from typing import Mapping

LOOPBACKS = frozenset(("127.0.0.1", "::1"))
HOSTED_MARKERS = ("RENDER", "RENDER_SERVICE_ID", "DYNO", "K_SERVICE", "WEBSITE_INSTANCE_ID", "AWS_LAMBDA_FUNCTION_NAME")


def normalized_host(host: str) -> str:
    host = host.strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return host.lower()


def launch_errors(host: str, env: Mapping[str, str], *, reload: bool = False, workers: int = 1) -> list[str]:
    """Return safe error codes; do not return secret values."""
    errors: list[str] = []
    actual = normalized_host(host)
    local = env.get("AGENTVERIFY_LOCAL_DEV_MODE") == "1"
    declared = normalized_host(env.get("AGENTVERIFY_LOCAL_BIND_HOST", ""))
    public = env.get("AGENTVERIFY_PUBLIC_MODE") == "1"
    cloud = env.get("AGENTVERIFY_CLOUD_MODE") == "1"
    hosted = any(env.get(marker) for marker in HOSTED_MARKERS)
    if local:
        if actual not in LOOPBACKS:
            errors.append("local_requires_loopback_listener")
        if declared not in LOOPBACKS or declared != actual:
            errors.append("local_bind_declaration_mismatch")
        if public or cloud or hosted:
            errors.append("local_conflicts_with_hosting")
    elif declared and env.get("AGENTVERIFY_LOCAL_DEV_MODE") != "1":
        # A stale declaration is not permission to enable a bypass.
        pass
    if local and env.get("AGENTVERIFY_REQUIRE_GUARDED_LOCAL_LAUNCH") == "1":
        if reload:
            errors.append("guarded_local_reload_forbidden")
        if workers != 1:
            errors.append("guarded_local_workers_forbidden")
    if reload and (public or cloud or hosted):
        errors.append("reload_forbidden_on_public_host")
    if workers < 1:
        errors.append("invalid_worker_count")
    if reload and workers != 1:
        errors.append("reload_workers_conflict")
    # V2.00: stricter startup-only policy for local development.
    from app.startup_policy import local_startup_errors
    errors.extend(local_startup_errors(host, env, reload=reload, workers=workers))
    # Reuse the V1.80 deployment configuration gate without logging secrets.
    from app.deployment_config import deployment_errors
    if deployment_errors(env):
        errors.append("deployment_configuration_invalid")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Guarded research Uvicorn launcher")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--reload", action="store_true")
    parser.add_argument("--workers", type=int, default=1)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        print("BLOCKED: invalid_port", file=sys.stderr)
        return 2
    problems = launch_errors(args.host, os.environ, reload=args.reload, workers=args.workers)
    if problems:
        print("BLOCKED: " + ",".join(problems), file=sys.stderr)
        return 2
    # The process-local guard is activated only after validating launch options.
    # Reload and multiple workers are prohibited when guard enforcement is on.
    if os.environ.get("AGENTVERIFY_LOCAL_DEV_MODE") == "1" and os.environ.get("AGENTVERIFY_REQUIRE_GUARDED_LOCAL_LAUNCH") == "1":
        from app.local_launch_guard import activate
        activate(normalized_host(args.host))
    # Import uvicorn only after all checks; no network bind occurs on rejection.
    import uvicorn
    uvicorn.run("app.main:app", host=normalized_host(args.host), port=args.port,
                reload=args.reload, workers=args.workers)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
