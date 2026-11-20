"""Research security configuration checks. Pure functions; no secrets logged."""
import base64
import binascii
import os

CLOUD_MARKERS = ("RENDER", "RENDER_SERVICE_ID", "DYNO", "K_SERVICE", "WEBSITE_INSTANCE_ID", "AWS_LAMBDA_FUNCTION_NAME")

def deployment_errors(env=None, *, include_startup=True):
    if env is None and include_startup:
        from app.startup import environment_changed, runtime_environment
        if environment_changed():
            return ["Startup configuration changed"]
        e = runtime_environment()
    else:
        e = os.environ if env is None else env
    errors=[]
    from app.credentials import backend_name, configuration_errors
    credential_backend=backend_name(e)
    if credential_backend != "legacy":
        errors.extend(configuration_errors(e))
    local=e.get("AGENTVERIFY_LOCAL_DEV_MODE")=="1"
    public=e.get("AGENTVERIFY_PUBLIC_MODE")=="1"
    cloud=e.get("AGENTVERIFY_CLOUD_MODE")=="1"
    hosted=any(e.get(k) for k in CLOUD_MARKERS)
    if local and (public or cloud or hosted):
        errors.append("Local development conflicts with public/cloud hosting")
    if local and e.get("AGENTVERIFY_LOCAL_BIND_HOST") not in ("127.0.0.1", "::1"):
        errors.append("Local development requires explicit loopback bind declaration")
    if cloud and not public:
        errors.append("Cloud mode requires public mode")
    if (public or cloud or hosted) and e.get("AGENTVERIFY_DEV_PAYMENT_PREVIEW")=="1":
        errors.append("Payment preview prohibited on public/cloud hosting")
    if public or cloud or hosted:
        if credential_backend == "legacy":
            keys=[k.strip() for k in e.get("AGENTVERIFY_API_KEYS", "").split(",") if k.strip()]
            if not keys or any(len(k)<32 for k in keys):
                errors.append("Public hosting requires strong API keys")
        raw=e.get("AGENTVERIFY_SIGNING_KEY_B64", "")
        try:
            if not raw or len(base64.b64decode(raw + "="*(-len(raw)%4), altchars=b"-_", validate=True))!=32:
                raise ValueError("invalid length")
        except (ValueError, binascii.Error):
            errors.append("Public hosting requires valid 32-byte signing seed")
    postgres=e.get("AGENTVERIFY_USAGE_BACKEND", "sqlite").lower()=="postgres"
    durable=e.get("AGENTVERIFY_DURABLE_QUOTAS")=="1"
    idempotency=e.get("AGENTVERIFY_IDEMPOTENCY_V390")=="1"
    if (public or cloud or hosted or durable or idempotency) and (postgres or durable or idempotency):
        managed = (e.get("AGENTVERIFY_POSTGRES_SCHEMA_MANAGED") == "1" or
                   (durable and e.get("AGENTVERIFY_QUOTA_SCHEMA_MANAGED") == "1") or
                   (idempotency and e.get("AGENTVERIFY_IDEMPOTENCY_SCHEMA_MANAGED") == "1"))
        if not managed:
            errors.append("Managed PostgreSQL schema required")
    if e.get("AGENTVERIFY_POSTGRES_SCHEMA", "public") != "public":
        errors.append("Unsupported PostgreSQL schema")
    return errors
