"""Zero-dependency HTTP backend for the GLASSBOX dashboard.

Built on ``http.server.ThreadingHTTPServer`` so it runs on the SIFT Workstation
with no extra packages. Serves the static SPA, a small REST API, and a
Server-Sent-Events stream that drives the live triage view.
"""

from __future__ import annotations

import json
import mimetypes
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from glassbox.version import __version__
from glassbox.web.session import TriageSession

_STATIC = Path(__file__).resolve().parent / "static"
_SESSION: Optional[TriageSession] = None
_RUN_LOCK = threading.Lock()

mimetypes.add_type("application/javascript", ".js")
mimetypes.add_type("application/javascript", ".mjs")
mimetypes.add_type("text/css", ".css")
mimetypes.add_type("image/svg+xml", ".svg")


# Content-Security-Policy: a forensic dashboard renders attacker-controlled
# strings (malware file names, command lines, IOCs pulled from evidence), so the
# browser is a real injection surface. This policy is architectural defense in
# depth: script may load ONLY from our own origin (no 'unsafe-inline'; the theme
# bootstrap and boot call live in external .js files for exactly this reason), so
# an injected <script> or data:/external script cannot execute. Inline *style*
# attributes are permitted because the SPA composes them programmatically and
# style injection is far lower risk than script execution.
_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "img-src 'self' data:; "
    "font-src 'self' https://fonts.gstatic.com; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "form-action 'none'; "
    "frame-ancestors 'none'"
)

_SECURITY_HEADERS = {
    "Content-Security-Policy": _CSP,
    "X-Content-Type-Options": "nosniff",        # no MIME sniffing
    "X-Frame-Options": "DENY",                  # legacy clickjacking defense
    "Referrer-Policy": "no-referrer",           # never leak the case URL
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}


class Handler(BaseHTTPRequestHandler):
    server_version = f"GLASSBOX/{__version__}"

    # ----- helpers ------------------------------------------------------ #
    def _security_headers(self) -> None:
        for name, value in _SECURITY_HEADERS.items():
            self.send_header(name, value)

    def _json(self, obj, status: int = 200) -> None:
        body = json.dumps(obj, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)

    def _file(self, rel: str) -> None:
        # default document
        if rel in ("", "/"):
            rel = "index.html"
        elif rel.startswith("/static/"):
            rel = rel[len("/static/"):]          # _STATIC already points at static/
        else:
            rel = rel.lstrip("/")
        target = (_STATIC / rel).resolve()
        try:
            target.relative_to(_STATIC)  # prevent path traversal
        except ValueError:
            self.send_error(403)
            return
        if not target.is_file():
            # SPA fallback to index.html for client routes
            target = _STATIC / "index.html"
            if not target.is_file():
                self.send_error(404)
                return
        ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        data = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")  # always serve the latest asset
        self._security_headers()
        self.end_headers()
        self.wfile.write(data)

    def _sse_event(self, obj) -> None:
        line = f"data: {json.dumps(obj, default=str)}\n\n"
        self.wfile.write(line.encode("utf-8"))
        self.wfile.flush()

    def log_message(self, fmt, *args):  # quiet logging
        return

    # ----- routing ------------------------------------------------------ #
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/state":
            return self._state()
        if path == "/api/report":
            return self._json(_SESSION.report or {})
        if path == "/api/a2a":
            return self._json({"messages": _SESSION.a2a()})
        if path == "/api/navigator":
            return self._json(_SESSION.navigator_layer())
        if path == "/api/diamond":
            return self._json(_SESSION.diamond_model())
        if path == "/api/speed":
            return self._json(_SESSION.speed())
        if path == "/api/audit":
            return self._json(_SESSION.audit_records())
        if path == "/api/guardrail":
            return self._json(_SESSION.guardrail_selftest())
        if path == "/api/replay":
            return self._json(_SESSION.replay_verify())
        if path == "/api/triage/stream":
            return self._triage_stream()
        if path.startswith("/api/"):
            return self._json({"error": "unknown endpoint"}, 404)
        # pages: landing at "/", dashboard SPA under "/app"
        if path == "/" or path == "/index.html":
            return self._file("landing.html")
        if path == "/app" or path.startswith("/app/") or path == "/app.html":
            return self._file("index.html")
        # static + everything else
        return self._file(path)

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/api/triage":
            # kick off a blocking run in a thread; client should prefer the SSE stream
            if _RUN_LOCK.locked():
                return self._json({"started": False, "reason": "already running"}, 409)
            threading.Thread(target=_run_locked, daemon=True).start()
            return self._json({"started": True}, 202)
        return self._json({"error": "unknown endpoint"}, 404)

    def _state(self):
        man = _SESSION.evidence_manifest()
        self._json({
            "case_id": _SESSION.case_id,
            "version": __version__,
            "demo": _SESSION.demo,
            "has_report": _SESSION.report is not None,
            "running": _RUN_LOCK.locked(),
            "evidence": man.get("evidence", []),
            "tools": _SESSION.ctx.toolkit.list_tools(),
            "max_iterations": _SESSION.max_iterations,
        })

    def _triage_stream(self):
        if not _RUN_LOCK.acquire(blocking=False):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            self._sse_event({"type": "error", "error": "triage already running"})
            return
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "keep-alive")
            self.send_header("X-Accel-Buffering", "no")
            self._security_headers()
            self.end_headers()
            for ev in _SESSION.stream_run():
                self._sse_event(ev)
        except (BrokenPipeError, ConnectionResetError):  # pragma: no cover
            pass
        finally:
            _RUN_LOCK.release()


def _run_locked():
    with _RUN_LOCK:
        _SESSION.run_blocking()


def serve(*, host: str = "127.0.0.1", port: int = 8787,
          case_dir: Optional[str] = None, evidence_dir: Optional[str] = None,
          demo: bool = True, max_iterations: int = 3, open_browser: bool = True,
          auto_run: bool = False) -> None:
    """Start the GLASSBOX dashboard server (blocking)."""
    global _SESSION
    _SESSION = TriageSession(case_dir=case_dir, evidence_dir=evidence_dir,
                             demo=demo, max_iterations=max_iterations)

    if auto_run:
        threading.Thread(target=_run_locked, daemon=True).start()

    httpd = ThreadingHTTPServer((host, port), Handler)
    url = f"http://{host}:{port}/"
    print("\n  GLASSBOX Dashboard")
    print(f"  case   : {_SESSION.case_id}  ({'demo/replay' if _SESSION.demo else 'live'})")
    print(f"  tools  : {len(_SESSION.ctx.toolkit.list_tools())} read-only MCP tools")
    print(f"  serving: {url}")
    print("  (Ctrl+C to stop)\n")
    if open_browser:
        try:
            import webbrowser
            threading.Timer(0.6, lambda: webbrowser.open(url)).start()
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  shutting down…")
    finally:
        httpd.server_close()
        _SESSION.cleanup()
