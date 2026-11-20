"""AV-013 (F02): request body size cap (pure ASGI, outermost middleware).

Default 64 KiB, configurable with AGENTVERIFY_MAX_BODY_BYTES (1024..8 MiB).
An invalid or out-of-range value falls back to the default, never to "no limit".
Oversized requests get 413 with a fixed message; the body is never echoed.
"""
import json
import os

DEFAULT_MAX_BODY_BYTES = 64 * 1024
_MIN, _MAX = 1024, 8 * 1024 * 1024
_BODY = json.dumps({"detail": "Request body too large"}).encode("ascii")


def max_body_bytes(env=None) -> int:
    raw = (os.environ if env is None else env).get("AGENTVERIFY_MAX_BODY_BYTES")
    if raw is None:
        return DEFAULT_MAX_BODY_BYTES
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_MAX_BODY_BYTES
    return value if _MIN <= value <= _MAX else DEFAULT_MAX_BODY_BYTES


async def _respond(send, status, body):
    await send({"type": "http.response.start", "status": status, "headers": [
        (b"content-type", b"application/json"), (b"content-length", str(len(body)).encode("ascii")),
        (b"connection", b"close")]})
    await send({"type": "http.response.body", "body": body})


class BodySizeLimitMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        limit = max_body_bytes()
        lengths = [v for n, v in scope["headers"] if n.lower() == b"content-length"]
        if len(lengths) > 1:
            return await _respond(send, 400, b'{"detail":"Invalid Content-Length"}')
        if lengths:
            if not lengths[0].isdigit():
                return await _respond(send, 400, b'{"detail":"Invalid Content-Length"}')
            if int(lengths[0]) > limit:
                return await _respond(send, 413, _BODY)
            return await self.app(scope, receive, send)
        # No Content-Length (chunked): buffer up to the cap, then replay.
        chunks, total = [], 0
        while True:
            message = await receive()
            if message["type"] != "http.request":  # e.g. disconnect
                return await self.app(scope, receive, send)
            chunk = message.get("body", b"")
            total += len(chunk)
            if total > limit:
                return await _respond(send, 413, _BODY)
            chunks.append(chunk)
            if not message.get("more_body", False):
                break
        replay = iter([{"type": "http.request", "body": b"".join(chunks), "more_body": False}])

        async def replayed():
            try:
                return next(replay)
            except StopIteration:
                return await receive()
        return await self.app(scope, replayed, send)
