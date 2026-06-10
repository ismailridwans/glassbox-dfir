# GLASSBOX Web Dashboard

A polished, browser-based command console for GLASSBOX — built on the Python
**standard library only** (`http.server` + Server-Sent Events). No Node, no
build step, no extra `pip` packages: it runs on the SANS SIFT Workstation out
of the box.

```bash
glassbox serve                 # offline demo case, opens http://127.0.0.1:8787
glassbox serve --case /cases/incident-001 --evidence /cases/incident-001/evidence
glassbox serve --port 9000 --no-browser
```

On first load the dashboard auto-starts a **live triage** so you watch the agent
work, then lands on the populated overview.

## Feature menu (left sidebar)

| View | What it shows |
|------|---------------|
| **Dashboard** | Stat tiles (findings, red-team verified, quarantined, ATT&CK), evidence-integrity / audit-chain / machine-speed banners, severity donut, tactic-coverage bars, top findings. |
| **Live Triage** | Real-time node-by-node execution trace over SSE — plan → collect → correlate → ATT&CK map → hallucination gate → red-team panel → self-correction loop → report. The demo centerpiece. |
| **Findings** | Filterable/searchable explorer; per-finding severity, confidence, NABAOS epistemic type, adversarial verdict, ATT&CK pills, IOCs, and expandable provenance + skeptic votes. |
| **Timeline** | Auto-generated incident narrative + unified cross-source chronological timeline. |
| **ATT&CK Matrix** | Kill-chain matrix grouped by tactic, colored by severity, with a one-click **Navigator layer** download (loads in the official MITRE ATT&CK Navigator). |
| **IOCs** | Indicators grouped by type, all **defanged**, copy-to-clipboard, source tool citation. |
| **Discrepancies** | Cross-source (disk-vs-memory) discrepancies: hidden processes, orphan connections, bad parents. |
| **Audit Trail** | The hash-chained, tamper-evident chain of custody with a **Re-verify chain** button. |
| **Guardrails** | One-click architectural guardrail self-test (no-write-tool, path-traversal, evidence-RO, audit-tamper, hallucination, HMAC) — PASS/FAIL per boundary. |
| **Forensic & Replay** | Deterministic replay (findings re-derived from the audit log), evidence-integrity table, and the Diamond Model of intrusion analysis. |

## Architecture

```
Browser SPA (vanilla JS, no build)            stdlib HTTP server (http.server)
  index.html  app.js (router+UI kit)   <-->     /api/state /report /a2a /navigator
  css/app.css api.js (fetch+EventSource)         /diamond /speed /audit /guardrail /replay
  js/views/*.js (self-registering)               /api/triage/stream  (Server-Sent Events)
        |                                                   |
        |  EventSource(/api/triage/stream)                  v
        +------------------------------------>  TriageSession → LangGraph triage engine
                                                 (same engine the CLI/MCP server use)
```

- **Backend:** `glassbox/web/server.py` (routing + SSE), `glassbox/web/session.py`
  (wraps `CaseContext`, streams node events, caches the report + derived artifacts).
- **Frontend:** `glassbox/web/static/` — `index.html` shell, `css/app.css` design
  system, `js/api.js` client, `js/app.js` framework (view registry, router, UI
  helper kit), `js/views/*.js` (one self-registering module per feature).
- The web layer calls the **exact same** triage engine as the CLI and the MCP
  server, so behavior never diverges across transports.

## Adding a view
Drop a `js/views/<id>.js` that calls `GLASSBOX.registerView(...)` and add one
`<script>` tag to `index.html`. See `js/CONTRACT.md` for the full contract.

## Security note
The web server binds to `127.0.0.1` by default (local-only). It exposes **read
endpoints plus a triage trigger** — it never exposes a write/shell endpoint, in
keeping with GLASSBOX's read-only, architecturally-guardrailed design.
