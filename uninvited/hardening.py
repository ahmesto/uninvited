"""Response hardening that applies to every route, in one place.

  SecurityHeaders  adds the standard browser security headers to every response,
                   a Content-Security-Policy to HTML, and CORS to the public feeds.
  HeadAsGet        answers HEAD with the headers GET would send and no body, so
                   monitors and link checkers that use HEAD get a real answer.

Both are plain ASGI middleware. Nothing here reads or changes a response body,
so they cost almost nothing and cannot disturb the streaming file responses.

The full CSP is sent as Report-Only unless the config says enforce. The page
needs inline script and style; fonts, map data, flags and the topojson client are
served from static/vendor, so no third party is listed but Cloudflare's own
analytics beacon. Watch the browser console for violations before enforcing.
Clickjacking protection is not report-only: frame-ancestors is enforced.
"""
from __future__ import annotations

from starlette.datastructures import MutableHeaders

# "report" while the policy is being proven against the real page, "enforce" after.
CSP_MODE = "report"

CSP_FULL = "; ".join([
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' https://static.cloudflareinsights.com",
    "style-src 'self' 'unsafe-inline'",
    "font-src 'self'",
    "img-src 'self' data:",
    "connect-src 'self' wss: https://cloudflareinsights.com",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
])
# Enforced. Who may put this site in a frame: itself, plus the owner's own site (Identity).
CSP_FRAMES = "frame-ancestors 'self'"

BASE_HEADERS = {
    "strict-transport-security": "max-age=31536000",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
    "cross-origin-opener-policy": "same-origin",
}


def cors_path(path: str) -> bool:
    """Public, read-only data that a browser on another site may fetch. The
    lookup, bulk and report endpoints are deliberately not here: they are
    rate limited per visitor and one of them writes."""
    return path.startswith("/feed/") or path in ("/api/blocklist", "/api/wordlist")


PREFLIGHT = {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET, HEAD, OPTIONS",
    "access-control-allow-headers": "If-None-Match, If-Modified-Since",
    "access-control-max-age": "86400",
}


class SecurityHeaders:
    def __init__(self, app, csp_mode: str | None = None, frames: str = CSP_FRAMES):
        self.app = app
        self.csp_mode = csp_mode or CSP_MODE
        self.frames = frames

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope["path"]

        if scope["method"] == "OPTIONS" and cors_path(path):
            headers = [(k.encode(), v.encode()) for k, v in {**BASE_HEADERS, **PREFLIGHT}.items()]
            await send({"type": "http.response.start", "status": 204, "headers": headers})
            await send({"type": "http.response.body", "body": b""})
            return

        async def wrapped(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for key, value in BASE_HEADERS.items():
                    if key not in headers:
                        headers[key] = value
                if headers.get("content-type", "").startswith("text/html"):
                    headers.append("content-security-policy", self.frames)
                    name = ("content-security-policy" if self.csp_mode == "enforce"
                            else "content-security-policy-report-only")
                    headers.append(name, CSP_FULL)
                # The self-hosted assets never change without a new file name in the page,
                # so browsers and the CDN may keep them for a week.
                if path.startswith("/static/vendor/") and message.get("status") == 200:
                    headers["cache-control"] = "public, max-age=604800"
                if cors_path(path):
                    headers["access-control-allow-origin"] = "*"
                    headers["access-control-expose-headers"] = "ETag, Last-Modified"
            await send(message)

        await self.app(scope, receive, wrapped)


class HeadAsGet:
    """HEAD is GET without the body. Run it as GET, drop the body, keep the headers
    (including the Content-Length GET would have sent)."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] != "HEAD":
            await self.app(scope, receive, send)
            return
        scope = dict(scope)
        scope["method"] = "GET"
        # Servers that can hand a file to the OS directly would bypass the body
        # filter below, so do not offer that.
        scope["extensions"] = {k: v for k, v in scope.get("extensions", {}).items()
                               if k != "http.response.pathsend"}
        done = False

        async def quiet(message):
            nonlocal done
            if message["type"] == "http.response.start":
                await send(message)
            elif message["type"] in ("http.response.body", "http.response.pathsend") and not done:
                done = True
                await send({"type": "http.response.body", "body": b"", "more_body": False})

        await self.app(scope, receive, quiet)
