"""AV-013 (F06/F15): remote-MCP allowed hosts from config, localhost-only by default.

Extra public hostnames come from AGENTVERIFY_MCP_ALLOWED_HOSTS (comma separated
host names, optional :port). Wildcards other than the loopback ":*" defaults are
rejected; a malformed entry raises (fail closed) rather than being ignored.
"""
import os
import re

_HOST = re.compile(r"^(?=.{1,253}(?::\d{1,5})?$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?::\d{1,5})?$")
_LOCAL_HOSTS = ["127.0.0.1:*", "localhost:*", "[::1]:*"]
_LOCAL_ORIGINS = ["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"]


def allowed_hosts_and_origins(env=None):
    e = os.environ if env is None else env
    hosts, origins = list(_LOCAL_HOSTS), list(_LOCAL_ORIGINS)
    for item in e.get("AGENTVERIFY_MCP_ALLOWED_HOSTS", "").split(","):
        item = item.strip().lower()
        if not item:
            continue
        if not _HOST.match(item):
            raise RuntimeError("Invalid AGENTVERIFY_MCP_ALLOWED_HOSTS entry")
        hosts.append(item)
        origins.append("https://" + item)
    return hosts, origins
