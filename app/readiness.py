"""Opt-in, operator-authenticated readiness checks with generic responses."""
import hmac
import os
from contextlib import closing


def enabled(env=None):
    return (os.environ if env is None else env).get("AGENTVERIFY_READINESS_ENABLED") == "1"


def check_operator_header(scope, env=None):
    env = os.environ if env is None else env
    expected = env.get("AGENTVERIFY_READINESS_KEY", "")
    if len(expected) < 32:
        return False
    values = [value for name, value in scope.get("headers", ())
              if name.lower() == b"x-agentverify-readiness-key"]
    if len(values) != 1:
        return False
    try:
        supplied = values[0].decode("latin-1")
        return hmac.compare_digest(supplied.encode(), expected.encode())
    except (UnicodeError, AttributeError):
        return False


def dependency_check(env=None):
    env = os.environ if env is None else env
    if env.get("AGENTVERIFY_PUBLIC_MODE") != "1":
        return False
    try:
        from app.startup import current_state, probe_dependencies
        state = current_state()
        if (state is None or not state.ready or
                not probe_dependencies(state.config, owner=state.owner)):
            return False
        from app.receipts import public_key_info
        public_key_info()
        return True
    except Exception:
        return False
