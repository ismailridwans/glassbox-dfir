"""Web dashboard tests: session manager, HTTP endpoints, static assets."""

import json
import threading
import time
import urllib.request
from pathlib import Path

import pytest

STATIC = Path(__file__).parent.parent / "src" / "glassbox" / "web" / "static"


# ----------------------------------------------------------------- session --
class TestSession:
    def test_stream_run_produces_report(self):
        from glassbox.web.session import TriageSession
        s = TriageSession(demo=True)
        try:
            events = list(s.stream_run())
            assert events[0]["type"] == "start"
            assert events[-1]["type"] == "done"
            assert any(e["type"] == "node" for e in events)
            assert s.report is not None
            assert len(s.report["findings"]) > 0
            assert s.report.get("duration_ms", 0) >= 0
        finally:
            s.cleanup()

    def test_derived_artifacts(self):
        from glassbox.web.session import TriageSession
        s = TriageSession(demo=True)
        try:
            list(s.stream_run())
            assert len(s.navigator_layer()["techniques"]) > 0
            assert "adversary" in s.diamond_model()
            assert s.audit_records()["valid"] is True
            assert s.guardrail_selftest()["all_passed"] is True
            assert s.replay_verify()["reproducible"] is True
            assert s.speed()["tool_executions"] > 0
        finally:
            s.cleanup()


# ----------------------------------------------------------------- static --
class TestStaticAssets:
    def test_core_files_exist(self):
        for rel in ("index.html", "css/app.css", "js/api.js", "js/app.js",
                    "js/views/dashboard.js"):
            assert (STATIC / rel).is_file(), f"missing {rel}"

    def test_index_references_views(self):
        html = (STATIC / "index.html").read_text(encoding="utf-8")
        for v in ("dashboard", "triage", "findings", "timeline", "attack",
                  "iocs", "discrepancies", "audit", "guardrails", "forensic"):
            assert f"views/{v}.js" in html, f"index.html missing view {v}"

    def test_all_view_files_present_and_register(self):
        views_dir = STATIC / "js" / "views"
        for v in ("dashboard", "triage", "findings", "timeline", "attack",
                  "iocs", "discrepancies", "audit", "guardrails", "forensic"):
            f = views_dir / f"{v}.js"
            assert f.is_file(), f"missing view file {v}.js"
            txt = f.read_text(encoding="utf-8")
            assert "GLASSBOX.registerView" in txt, f"{v}.js does not register a view"
            assert f'"{v}"' in txt or f"'{v}'" in txt, f"{v}.js registers wrong id"


# ----------------------------------------------------------------- HTTP --
@pytest.fixture(scope="module")
def server():
    from glassbox.web import server as srv
    from glassbox.web.session import TriageSession
    srv._SESSION = TriageSession(demo=True)
    srv._SESSION.run_blocking()
    from http.server import ThreadingHTTPServer
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), srv.Handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    time.sleep(0.3)
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()
    srv._SESSION.cleanup()


def _get(url):
    with urllib.request.urlopen(url, timeout=10) as r:
        return r.status, r.headers.get("Content-Type", ""), r.read()


class TestHTTP:
    def test_index(self, server):
        st, ct, body = _get(server + "/")
        assert st == 200 and "text/html" in ct
        assert b"GLASSBOX" in body

    def test_root_serves_landing(self, server):
        _, _, body = _get(server + "/")
        # landing page hero markers (not the SPA shell)
        assert b'class="hero' in body
        assert b"Launch Dashboard" in body

    def test_app_serves_spa(self, server):
        st, ct, body = _get(server + "/app")
        assert st == 200 and "text/html" in ct
        assert b'id="app"' in body
        assert b"views/dashboard.js" in body

    def test_landing_assets_present(self, server):
        st, ct, _ = _get(server + "/static/css/landing.css")
        assert st == 200 and "text/css" in ct
        st2, ct2, _ = _get(server + "/static/js/landing.js")
        assert st2 == 200 and "javascript" in ct2

    def test_css_content_type(self, server):
        st, ct, _ = _get(server + "/static/css/app.css")
        assert st == 200 and "text/css" in ct

    def test_js_content_type(self, server):
        st, ct, _ = _get(server + "/static/js/app.js")
        assert st == 200 and "javascript" in ct

    def test_api_state(self, server):
        st, ct, body = _get(server + "/api/state")
        assert st == 200 and "application/json" in ct
        d = json.loads(body)
        assert d["has_report"] is True
        assert len(d["tools"]) > 10

    def test_api_report(self, server):
        _, _, body = _get(server + "/api/report")
        d = json.loads(body)
        assert len(d["findings"]) > 0

    def test_api_guardrail(self, server):
        _, _, body = _get(server + "/api/guardrail")
        assert json.loads(body)["all_passed"] is True

    def test_api_replay(self, server):
        _, _, body = _get(server + "/api/replay")
        assert json.loads(body)["reproducible"] is True

    def test_api_navigator(self, server):
        _, _, body = _get(server + "/api/navigator")
        assert len(json.loads(body)["techniques"]) > 0

    def test_unknown_api_404(self, server):
        import urllib.error
        with pytest.raises(urllib.error.HTTPError) as exc:
            _get(server + "/api/nope")
        assert exc.value.code == 404
