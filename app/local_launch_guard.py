"""Opt-in, process-local evidence that the guarded launcher ran.

This is a defence-in-depth guard, not proof of OS socket binding. Do not
consider environment variables or HTTP Host headers proof of a safe listener.
"""
import os

_guard_pid = None
_guard_host = None


def activate(host: str) -> None:
    """Called by the validated launcher immediately before uvicorn.run."""
    global _guard_pid, _guard_host
    if host not in ('127.0.0.1', '::1'):
        raise ValueError('unsafe_local_listener')
    _guard_pid, _guard_host = os.getpid(), host


def guarded_local_process(env=None) -> bool:
    e = os.environ if env is None else env
    return (_guard_pid == os.getpid() and
            _guard_host in ('127.0.0.1', '::1') and
            e.get('AGENTVERIFY_LOCAL_BIND_HOST') == _guard_host)
