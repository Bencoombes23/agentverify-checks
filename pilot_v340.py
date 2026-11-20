"""Runnable external client + disposable real-app pilot. No external endpoints.

Only generated synthetic credentials/signing material are used. The client verifier
does not import app.receipts or trust a key merely because a receipt supplies it.
"""
import base64
from copy import deepcopy
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from process_v340 import ProcessTree

ROOT = Path(__file__).resolve().parent


class PilotFailure(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def b64(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def canonical_payload(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def verify_issuer_receipt(receipt, trusted_public_key):
    """Integrity + configured issuer only. Check payload.result.status separately."""
    try:
        if set(receipt) != {"payload", "algorithm", "public_key", "signature"}:
            return False
        if receipt["algorithm"] != "Ed25519" or receipt["public_key"] != trusted_public_key:
            return False
        def decode(text):
            return base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True)
        public = Ed25519PublicKey.from_public_bytes(decode(trusted_public_key))
        public.verify(decode(receipt["signature"]), canonical_payload(receipt["payload"]))
        return True
    except (ValueError, TypeError, KeyError, InvalidSignature, RecursionError):
        return False


def file_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def workspace_hashes(root):
    result = {}
    def scan_error(error):
        raise error
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=scan_error):
        dirs[:] = sorted(d for d in dirs if d not in {".git", ".venv"})
        for name in (*dirs, *files):
            path = Path(directory) / name
            if path.is_symlink() or path.is_junction():
                raise ValueError("Workspace links require review")
        for name in files:
            path = Path(directory) / name
            result[path.relative_to(root).as_posix()] = file_hash(path)
    return result


def request(port, method, path, *, key=None, duplicate=False, payload=None, raw_body=None):
    """Only the known child server's loopback port; preserve repeated fields."""
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    body = raw_body if raw_body is not None else None if payload is None else json.dumps(payload).encode()
    try:
        connection.putrequest(method, path)
        if key is not None:
            connection.putheader("X-API-Key", key)
            if duplicate:
                connection.putheader("x-api-key", key)
        if body is not None:
            connection.putheader("Content-Type", "application/json")
            connection.putheader("Content-Length", str(len(body)))
        connection.endheaders(body)
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


def require(condition, code):
    if not condition:
        raise PilotFailure(code)  # Static scenario code, never credentials or response contents.


def run_pilot(output=None):
    parent = Path(tempfile.gettempdir()).resolve()
    if parent.is_relative_to(ROOT):
        raise ValueError("Temporary root must be outside source tree")
    output = Path(tempfile.mkdtemp(prefix="agentverify-pilot-v340-", dir=parent)) if output is None else Path(output)
    if any(p.is_symlink() or p.is_junction() for p in (output, *output.parents)):
        raise ValueError("Output links require review")
    output = output.resolve()
    if output.is_relative_to(ROOT) or ROOT.is_relative_to(output):
        raise ValueError("Output overlaps source tree")
    if output.exists() and any(output.iterdir()):
        raise ValueError("Output must be a new or empty disposable directory")
    output.mkdir(parents=True, exist_ok=True)
    before = workspace_hashes(ROOT)
    report = {"pilot_status": "BLOCKED", "scenarios": {}, "output": str(output),
              "scope": "synthetic localhost pilot; no production readiness claim"}
    process = None
    tree = None
    phase = "prepare"
    try:
        source = output / "source"
        app_dir = source / "app"
        app_dir.mkdir(parents=True)
        files = sorted((ROOT / "app").glob("*.py"))
        require(bool(files), "missing-app-source")
        report["app_source_sha256"] = {}
        for path in files:
            require(not path.is_symlink(), "app-source-link")
            shutil.copyfile(path, app_dir / path.name)
            digest = file_hash(path)
            require(file_hash(app_dir / path.name) == digest, "copy-mismatch")
            report["app_source_sha256"]["app/" + path.name] = digest
        key = secrets.token_urlsafe(40)
        seed = secrets.token_bytes(32)
        trusted = b64(Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        report["trusted_issuer_fingerprint"] = hashlib.sha256(trusted.encode()).hexdigest()
        markers = {"RENDER", "RENDER_SERVICE_ID", "DYNO", "K_SERVICE", "WEBSITE_INSTANCE_ID",
                   "AWS_LAMBDA_FUNCTION_NAME", "RAILWAY_ENVIRONMENT", "VERCEL", "FLY_APP_NAME", "PORT",
                   "FORWARDED_ALLOW_IPS", "UVICORN_FORWARDED_ALLOW_IPS", "DATABASE_URL"}
        env = {k: v for k, v in os.environ.items()
               if not k.upper().startswith(("AGENTVERIFY_", "PYTHON", "PYTEST_", "PG", "GIT_")) and k.upper() not in markers}
        env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONNOUSERSITE="1", PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
                   AGENTVERIFY_PUBLIC_MODE="1", AGENTVERIFY_API_KEYS=key, AGENTVERIFY_SIGNING_KEY_B64=b64(seed),
                   AGENTVERIFY_USAGE_DB=str(output / "synthetic-usage.sqlite"), AGENTVERIFY_RATE_LIMIT_PER_MINUTE="100000",
                   TEMP=str(output), TMP=str(output), TMPDIR=str(output))
        port_file = output / "bound-port.txt"
        script = """
import pathlib, sys, uvicorn
from app.main import app
config = uvicorn.Config(app, host='127.0.0.1', port=0, lifespan='off', access_log=False, log_level='warning')
with config.bind_socket() as bound:
    with open(sys.argv[1], 'x', encoding='ascii') as stream:
        stream.write(str(bound.getsockname()[1]))
    uvicorn.Server(config).run(sockets=[bound])
"""
        phase = "startup"
        with (output / "server.log").open("xb") as log:
            tree = ProcessTree([sys.executable, "-B", "-c", script, str(port_file)],
                               cwd=source, env=env, stdout=log, stderr=log)
            process = tree.process
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            require(process.poll() is None, "server-exited")
            try:
                port = int(port_file.read_text(encoding="ascii"))
                if request(port, "GET", "/health")[0] == 200:
                    break
            except (OSError, ValueError, http.client.HTTPException):
                pass
            time.sleep(.03)
        else:
            raise PilotFailure("startup-timeout")
        phase = "acceptance"
        scenarios = report["scenarios"]
        claim = {"calculation_type": "arithmetic", "claimed_result": "3", "inputs": {"a": "1", "b": "2"}}
        status, result = request(port, "POST", "/verify", key=key, payload=claim)
        require(status == 200 and result["status"] == "passed", "passing-evaluation")
        scenarios["passing_calculation"] = True
        status, public = request(port, "GET", "/receipts/public-key", key=key)
        require(status == 200 and public["public_key"] == trusted, "issuer-pin")
        scenarios["issuer_matches_independent_pin"] = True
        for name, expected, value in (("passing_receipt", "passed", "3"), ("failed_receipt", "failed", "99")):
            status, receipt = request(port, "POST", "/verify/signed", key=key,
                                      payload={**claim, "claimed_result": value})
            require(status == 200 and receipt["payload"]["result"]["status"] == expected, name)
            require(verify_issuer_receipt(receipt, trusted), "client-signature-" + name)
            require(request(port, "POST", "/receipts/check", key=key, payload=receipt) == (200, {"valid": True}), "server-signature")
            scenarios[name] = {"http_status": status, "calculation_status": expected, "client_signature_valid": True}
        tampered = deepcopy(receipt)
        tampered["payload"]["result"]["status"] = "passed"
        require(not verify_issuer_receipt(tampered, trusted), "client-tamper")
        require(request(port, "POST", "/receipts/check", key=key, payload=tampered) == (200, {"valid": False}), "server-tamper")
        scenarios["tampering_rejected_by_client_and_server"] = True
        for name, credential, duplicate in (("missing_key", None, False), ("invalid_key", "synthetic-invalid", False),
                                             ("duplicate_key", key, True)):
            status, body = request(port, "POST", "/verify", key=credential, duplicate=duplicate, payload=claim)
            require(status == 401 and body == {"detail": "Invalid or missing API key"}, name)
            require(key not in json.dumps(body), "credential-disclosure")
            scenarios[name] = {"http_status": status}
        require(request(port, "POST", "/verify", key=key, payload={})[0] == 422, "validation-error")
        scenarios["invalid_request"] = {"http_status": 422}
        status, schema = request(port, "GET", "/openapi.json", key=key)
        require(status == 200 and schema["components"]["securitySchemes"]["ApiKeyAuth"]["name"] == "X-API-Key", "openapi-auth")
        scenarios["documented_authentication"] = True
        # No new budget policy: observe existing parser handling on malformed input.
        status, body = request(port, "POST", "/verify", key=key, raw_body=b'{"x":' * 10000 + b'0' + b'}' * 10000)
        require(status == 422 and body == {"detail": [{"type": "invalid_request", "loc": ["body"],
                "msg": "Invalid request; detailed errors could not be safely serialized"}]}, "deep-json-error")
        scenarios["deep_json_generic_error"] = {"http_status": status}
        report["pilot_status"] = "PASS"
    except Exception as exc:
        report["error"] = {"phase": phase, "type": type(exc).__name__,
                           "code": exc.code if isinstance(exc, PilotFailure) else "unexpected-error"}
    finally:
        if tree is not None:
            try:
                tree.close()
            except Exception as exc:
                report["cleanup_error"] = type(exc).__name__
                report["pilot_status"] = "BLOCKED"
        report["process_tree_stopped"] = tree is not None and tree.stopped
        report["server_stopped"] = (process is not None and process.poll() is not None and
                                    report["process_tree_stopped"] and "cleanup_error" not in report)
        try:
            after = workspace_hashes(ROOT)
            report["workspace_unchanged"] = before == after
            if before != after:
                report["pilot_status"] = "BLOCKED"
            source_unchanged = all(file_hash(output / "source" / p) == digest
                                   for p, digest in report.get("app_source_sha256", {}).items())
            report["copied_source_unchanged"] = source_unchanged
            if not source_unchanged or not report["server_stopped"]:
                report["pilot_status"] = "BLOCKED"
        except Exception as exc:
            report["integrity_error"] = type(exc).__name__
            report["pilot_status"] = "BLOCKED"
        (output / "pilot_acceptance.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


if __name__ == "__main__":
    result = run_pilot()
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["pilot_status"] == "PASS" else 1)
