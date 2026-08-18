"""Rejects oversized requests before Starlette/FastAPI reads the body (security review,
M8 Stage 4). Every upload route already re-checks its own tighter limit (e.g.
`settings.max_upload_bytes`) — but only after calling `await file.read()` / `await
request.form()` / letting Pydantic parse the JSON body, all of which fully buffer (or spool
to disk) the request first. A raw ASGI middleware, not `BaseHTTPMiddleware`, so this never
touches the body itself — it inspects the declared `Content-Length` header and short-circuits
before `receive()` is ever called by downstream code.

Residual gap: a request sent without a `Content-Length` header (e.g. real chunked
transfer-encoding) isn't caught here. Pair this with a reverse-proxy/CDN body-size limit in
production for defense in depth — see DEPLOYMENT.md.
"""

from __future__ import annotations

from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Receive, Scope, Send


class MaxBodySizeMiddleware:
    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            content_length = next(
                (v for k, v in scope.get("headers", []) if k == b"content-length"), None
            )
            if content_length is not None:
                try:
                    declared_size = int(content_length)
                except ValueError:
                    declared_size = None
                if declared_size is not None and declared_size > self.max_bytes:
                    response = PlainTextResponse("Request body too large.", status_code=413)
                    await response(scope, receive, send)
                    return

        await self.app(scope, receive, send)
