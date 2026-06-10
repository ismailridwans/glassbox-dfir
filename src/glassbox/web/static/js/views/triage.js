/* Live Triage — the demo centerpiece. Streams the agent's live execution trace
 * over SSE and renders a real-time node-by-node trace + result panel.
 * Contract: GLASSBOX.registerView(id, { title, sub, order, icon, badge?, render }).
 * Exposes a global GLASSBOX.startTriage() that owns the SSE stream + UI.
 */
(function () {
  const ICON = "<svg viewBox='0 0 24 24'><circle cx='12' cy='12' r='3.2' fill='none' stroke='currentColor' stroke-width='1.6'/><path d='M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M19.1 4.9L17 7M7 17l-2.1 2.1' stroke='currentColor' stroke-width='1.6' stroke-linecap='round'/></svg>";

  /* Module-level handles so startTriage() can append into the live view even
   * across re-renders. render() rebuilds these every time it runs. */
  let traceEl = null;     // the .trace container we append rows into
  let headerEl = null;    // case-header host (filled on 'start')
  let resultEl = null;    // result-panel host (filled on 'done')
  let runBtn = null;      // the primary Start button
  let t0 = 0;             // wall-clock start for fallback timing
  let nodeCount = 0;      // rows appended this run

  const U = () => (window.GLASSBOX && window.GLASSBOX.ui) || null;

  function short(sha) {
    if (!sha) return "—";
    return String(sha).length > 18 ? String(sha).slice(0, 10) + "…" + String(sha).slice(-6) : String(sha);
  }
  function baseName(p) {
    if (!p) return "(unknown)";
    const parts = String(p).split(/[\\/]/);
    return parts[parts.length - 1] || p;
  }

  /* glyph per node kind — purely cosmetic */
  function glyphFor(node) {
    return ({
      intake: "◆", plan: "▸", collect: "↓", analyze: "✶",
      verify: "✓", adversarial_verify: "⚔", report: "▣",
    })[node] || "•";
  }

  /* ---- the global live-stream driver ---- */
  function startTriage() {
    const G = window.GLASSBOX;
    const ui = U();
    if (!G || !ui || !traceEl) return;          // view not mounted yet
    const { el } = ui;

    // reset live containers for a fresh run
    traceEl.innerHTML = "";
    if (headerEl) headerEl.innerHTML = "";
    if (resultEl) resultEl.innerHTML = "";
    nodeCount = 0;
    t0 = performance.now();
    if (runBtn) { runBtn.disabled = true; runBtn.textContent = "Triage running…"; }

    G.setStatus("running", "running");

    const onEvent = (ev) => {
      try {
        if (ev.type === "start") renderStart(ev, ui);
        else if (ev.type === "node") appendNode(ev, ui);
        else if (ev.type === "done") renderDone(ev, ui);
      } catch (e) { /* never let a malformed event throw out of the stream */ console.error(e); }
    };
    const onDone = () => {
      // renderDone (fired on the 'done' event just before this) owns ctx.refresh()
      if (runBtn) { runBtn.disabled = false; runBtn.textContent = "Run Again"; }
    };
    const onError = (e) => {
      const msg = (e && e.error) ? e.error : "stream error";
      G.setStatus("error", msg);
      if (runBtn) { runBtn.disabled = false; runBtn.textContent = "Retry Triage"; }
      if (traceEl) traceEl.appendChild(el("div", { class: "trace-row is-new redteam" }, [
        el("div", { class: "t-time", text: ((performance.now() - t0) / 1000).toFixed(2) + "s" }),
        el("div", { class: "t-ic", text: "!" }),
        el("div", {}, [
          el("div", { class: "t-label", style: { color: "var(--bad)" }, text: "Stream error" }),
          el("div", { class: "t-detail", text: msg }),
        ]),
      ]));
    };

    G.api.streamTriage(onEvent, onDone, onError);
  }

  function renderStart(ev, ui) {
    const { el, badge, pill } = ui;
    if (!headerEl) return;
    headerEl.innerHTML = "";
    const evidence = ev.evidence || [];
    const tools = ev.tools || [];

    const rows = evidence.length
      ? evidence.map((f) => el("div", { class: "row wrap", style: { gap: "10px", padding: "7px 0", borderBottom: "1px solid #1a2538" } }, [
          el("span", { class: "badge low mono", text: (f.type || "?").toUpperCase() }),
          el("b", { style: { fontSize: "13px" }, text: baseName(f.path) }),
          el("span", { class: "mono faint", style: { fontSize: "11.5px" }, text: short(f.sha256) }),
          f.bytes != null ? el("span", { class: "faint", style: { fontSize: "11.5px", marginLeft: "auto" }, text: ui.fmtNum(f.bytes) + " B" }) : null,
        ]))
      : [el("div", { class: "faint", text: "No evidence files in manifest." })];

    headerEl.appendChild(el("div", { class: "card", style: { padding: "16px 18px", marginBottom: "14px" } }, [
      el("div", { class: "row wrap", style: { justifyContent: "space-between", marginBottom: "10px" } }, [
        el("div", { class: "row", style: { gap: "10px" } }, [
          el("span", { class: "loader" }),
          el("b", { style: { fontSize: "15px", letterSpacing: ".02em" }, text: "CASE " + (ev.case_id || "—") }),
          badge("LIVE", "good"),
        ]),
        el("div", { class: "row wrap", style: { gap: "8px" } }, [
          pill(evidence.length + " evidence"),
          pill(tools.length + " tools"),
        ]),
      ]),
      el("div", { style: { marginTop: "4px" } }, rows),
    ]));
  }

  function appendNode(ev, ui) {
    const { el } = ui;
    if (!traceEl) return;
    nodeCount++;
    const node = ev.node || "";
    const elapsed = ev.elapsed_ms != null ? ev.elapsed_ms : (performance.now() - t0);
    let cls = "trace-row is-new";
    if (node === "verify") cls += " verify";
    if (node === "adversarial_verify") cls += " redteam";

    const labelChildren = [el("span", { text: ev.label || node })];
    // mark the planning iteration visually
    if (node === "plan") {
      const it = ev.data && ev.data.iteration;
      if (it != null) labelChildren.push(el("span", {
        class: "badge mono", style: { marginLeft: "8px", color: "var(--accent)", borderColor: "#22d3ee55", background: "#0e2a3a" },
        text: "ITER " + it,
      }));
    }
    if (node === "adversarial_verify") labelChildren.push(el("span", { class: "badge bad", style: { marginLeft: "8px" }, text: "RED-TEAM" }));
    if (node === "verify") labelChildren.push(el("span", { class: "badge good", style: { marginLeft: "8px" }, text: "GROUNDED" }));

    const row = el("div", { class: cls }, [
      el("div", { class: "t-time", text: (elapsed / 1000).toFixed(2) + "s" }),
      el("div", { class: "t-ic", text: glyphFor(node) }),
      el("div", {}, [
        el("div", { class: "t-label" }, labelChildren),
        ev.detail ? el("div", { class: "t-detail", text: ev.detail }) : null,
      ]),
    ]);
    traceEl.appendChild(row);
    // keep the newest row in view inside the scrolling trace
    if (traceEl.parentElement) traceEl.parentElement.scrollTop = traceEl.parentElement.scrollHeight;
  }

  function renderDone(ev, ui) {
    const { el, stat } = ui;
    const G = window.GLASSBOX;

    // success summary line at the end of the trace
    if (traceEl) {
      traceEl.appendChild(el("div", { class: "trace-row is-new verify" }, [
        el("div", { class: "t-time", text: ((ev.duration_ms || 0) / 1000).toFixed(2) + "s" }),
        el("div", { class: "t-ic", text: "✓" }),
        el("div", {}, [
          el("div", { class: "t-label", style: { color: "var(--good)" }, text: "Triage complete" }),
          el("div", { class: "t-detail", text: nodeCount + " step(s) executed · report generated" }),
        ]),
      ]));
    }

    const r = ev.report || {};
    const adv = r.adversarial || {};
    const findings = (r.findings || []).length;
    if (resultEl) {
      resultEl.innerHTML = "";
      resultEl.appendChild(el("div", { class: "grid cols-4", style: { marginTop: "16px" } }, [
        stat("Duration", ((ev.duration_ms || r.duration_ms || 0) / 1000).toFixed(2) + "s", { tone: "accent", foot: (r.iterations_used != null ? r.iterations_used : "?") + "/" + (r.max_iterations != null ? r.max_iterations : "?") + " iterations" }),
        stat("Findings", findings, { foot: "reportable after verification" }),
        stat("Red-Team Upheld", adv.upheld != null ? adv.upheld : "—", { tone: "good", foot: (adv.demoted != null ? adv.demoted + " demoted" : "survived adversarial panel") }),
        stat("Refuted / Quarantined", (adv.refuted != null ? adv.refuted : (r.refuted || []).length) + " / " + (r.quarantined || []).length, { tone: "warn", foot: "false positives · unsupported" }),
      ]));
      resultEl.appendChild(el("div", { class: "row", style: { gap: "10px", marginTop: "14px" } }, [
        el("button", { class: "btn btn-primary", text: "View Findings →", onclick: () => G.go && G.go("findings") }),
        el("button", { class: "btn btn-ghost", text: "Full Dashboard →", onclick: () => G.go && G.go("dashboard") }),
      ]));
    }

    G.setStatus("done", "complete");
    if (G.ctxRefresh) G.ctxRefresh();
  }

  GLASSBOX.registerView("triage", {
    title: "Live Triage", sub: "real-time agent execution", order: 20, icon: ICON,
    badge: (ctx) => (ctx.report && ctx.report.findings) ? "✓" : null,
    render(root, ctx) {
      const { ui } = ctx;
      const { el, card } = ui;

      // stash navigation + refresh so the global driver can reach them
      window.GLASSBOX.go = ctx.go;
      window.GLASSBOX.ctxRefresh = ctx.refresh;
      window.GLASSBOX.startTriage = startTriage;

      const hasReport = !!(ctx.report && ctx.report.findings);

      /* ---- hero / launch panel ---- */
      const startLabel = hasReport ? "Run Again" : "Start Triage";
      runBtn = el("button", {
        class: "btn btn-primary",
        style: { fontSize: "15px", padding: "13px 26px", letterSpacing: ".02em" },
        text: startLabel,
        onclick: () => startTriage(),
      });

      const hero = el("div", {
        class: "card",
        style: {
          padding: "26px 28px", marginBottom: "16px",
          background: "radial-gradient(700px 300px at 80% -40%, #22d3ee14, transparent 60%), linear-gradient(180deg, var(--panel), var(--bg-2))",
          border: "1px solid #22d3ee33",
        },
      }, [
        el("div", { class: "row wrap", style: { justifyContent: "space-between", gap: "18px" } }, [
          el("div", {}, [
            el("div", { class: "row", style: { gap: "9px", marginBottom: "8px" } }, [
              el("span", { class: "nav-ic", style: { color: "var(--accent)", width: "26px", height: "26px" }, html: ICON.replace("viewBox", "width='26' height='26' viewBox") }),
              el("h2", { style: { margin: 0, fontSize: "22px", fontWeight: 800, letterSpacing: ".01em" }, text: "Autonomous DFIR Triage" }),
            ]),
            el("div", { class: "muted", style: { fontSize: "13px", maxWidth: "620px", lineHeight: 1.55 },
              text: "Watch the agent hash evidence, plan, collect, analyze, then adversarially red-team every claim — grounded, verified, and hash-chained in real time." }),
          ]),
          el("div", { class: "row", style: { gap: "10px" } }, [runBtn]),
        ]),
      ]);
      root.appendChild(hero);

      /* ---- last-run summary (only if a report already exists) ---- */
      if (hasReport) {
        const r = ctx.report;
        const adv = r.adversarial || {};
        const lastBody = el("div", { class: "grid cols-4" }, [
          ui.stat("Duration", ((r.duration_ms || 0) / 1000).toFixed(2) + "s", { tone: "accent",
            foot: (r.iterations_used != null ? r.iterations_used : "?") + "/" + (r.max_iterations != null ? r.max_iterations : "?") + " iterations" }),
          ui.stat("Findings", (r.findings || []).length, { foot: (r.evidence_types || []).length + " evidence type(s)" }),
          ui.stat("Red-Team Upheld", adv.upheld != null ? adv.upheld : "—", { tone: "good",
            foot: (adv.demoted != null ? adv.demoted + " demoted" : "survived panel") }),
          ui.stat("Refuted / Quarantined",
            (adv.refuted != null ? adv.refuted : (r.refuted || []).length) + " / " + (r.quarantined || []).length,
            { tone: "warn", foot: "false positives · unsupported" }),
        ]);
        root.appendChild(card("Last Run", lastBody, {
          sub: r.case_id || "",
          action: el("button", { class: "btn btn-sm btn-ghost", text: "Dashboard →", onclick: () => ctx.go("dashboard") }),
        }));
        root.appendChild(el("div", { style: { height: "16px" } }));
      }

      /* ---- live case header host (filled on 'start') ---- */
      headerEl = el("div");
      root.appendChild(headerEl);

      /* ---- live trace container (rebuilt on every render) ---- */
      traceEl = el("div", { class: "trace" });
      const traceScroll = el("div", { style: { maxHeight: "440px", overflow: "auto" } }, traceEl);
      const traceCard = card("Live Execution Trace", traceScroll, {
        sub: "node-by-node",
        bodyClass: "",
      });
      root.appendChild(traceCard);

      // initial empty hint inside the trace
      if (!hasReport) {
        traceEl.appendChild(el("div", { class: "empty", style: { padding: "34px 20px" } }, [
          el("div", { html: ICON.replace("viewBox", "width='40' height='40' viewBox") }),
          el("div", { text: "Press Start Triage to stream live agent execution." }),
        ]));
      } else {
        traceEl.appendChild(ui.empty("Re-run to stream a fresh live trace."));
      }

      /* ---- result panel host (filled on 'done') ---- */
      resultEl = el("div");
      root.appendChild(resultEl);
    },
  });
})();
