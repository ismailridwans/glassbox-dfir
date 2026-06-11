/* Dashboard v2 — mature premium layout:
   overview header → KPI cards (count-up) → kill-chain chart + threat posture → findings table. */
(function () {
  const ICON = "<svg viewBox='0 0 24 24'><rect x='3' y='3' width='8' height='8' rx='2' fill='none' stroke='currentColor' stroke-width='1.6'/><rect x='13' y='3' width='8' height='5' rx='2' fill='none' stroke='currentColor' stroke-width='1.6'/><rect x='13' y='11' width='8' height='10' rx='2' fill='none' stroke='currentColor' stroke-width='1.6'/><rect x='3' y='13' width='8' height='8' rx='2' fill='none' stroke='currentColor' stroke-width='1.6'/></svg>";

  const TACTIC_ORDER = ["Reconnaissance","Resource Development","Initial Access","Execution",
    "Persistence","Privilege Escalation","Defense Evasion","Credential Access","Discovery",
    "Lateral Movement","Collection","Command and Control","Exfiltration","Impact"];

  // icons used in KPI cards / section heads
  const I = {
    findings: "<svg viewBox='0 0 24 24'><path d='M4 6h16M4 12h10M4 18h7' stroke='currentColor' stroke-width='1.9' stroke-linecap='round'/></svg>",
    shield: "<svg viewBox='0 0 24 24'><path d='M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z' fill='none' stroke='currentColor' stroke-width='1.7' stroke-linejoin='round'/><path d='M9 12l2 2 4-4' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'/></svg>",
    alert: "<svg viewBox='0 0 24 24'><path d='M12 3l9 16H3z' fill='none' stroke='currentColor' stroke-width='1.7' stroke-linejoin='round'/><path d='M12 9v4M12 16.5v.5' stroke='currentColor' stroke-width='1.9' stroke-linecap='round'/></svg>",
    grid: "<svg viewBox='0 0 24 24'><rect x='3' y='3' width='7' height='7' rx='1.6' fill='none' stroke='currentColor' stroke-width='1.7'/><rect x='14' y='3' width='7' height='7' rx='1.6' fill='none' stroke='currentColor' stroke-width='1.7'/><rect x='3' y='14' width='7' height='7' rx='1.6' fill='none' stroke='currentColor' stroke-width='1.7'/><rect x='14' y='14' width='7' height='7' rx='1.6' fill='none' stroke='currentColor' stroke-width='1.7'/></svg>",
    pulse: "<svg viewBox='0 0 24 24'><path d='M3 12h4l2-6 4 12 2-6h6' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'/></svg>",
    donut: "<svg viewBox='0 0 24 24'><circle cx='12' cy='12' r='8.5' fill='none' stroke='currentColor' stroke-width='1.6'/><path d='M12 3.5A8.5 8.5 0 0120.5 12' fill='none' stroke='currentColor' stroke-width='2.4' stroke-linecap='round'/></svg>",
    table: "<svg viewBox='0 0 24 24'><rect x='3' y='4' width='18' height='16' rx='2.4' fill='none' stroke='currentColor' stroke-width='1.6'/><path d='M3 9h18M9 9v11' stroke='currentColor' stroke-width='1.4'/></svg>",
  };

  const reduceMotion = window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches;

  function countUp(node, to, dur) {
    to = Number(to) || 0;
    if (reduceMotion || to === 0) { node.textContent = String(to); return; }
    dur = dur || 750;
    const start = performance.now();
    (function frame(now) {
      const t = Math.min(1, (now - start) / dur);
      node.textContent = String(Math.round(to * (1 - Math.pow(1 - t, 3))));
      if (t < 1) requestAnimationFrame(frame);
      else node.textContent = String(to);
    })(performance.now());
    // safety net: guarantee the final value even if rAF is throttled (background tab / headless)
    setTimeout(() => { node.textContent = String(to); }, dur + 90);
  }

  GLASSBOX.registerView("dashboard", {
    title: "Dashboard", sub: "incident overview", order: 10, icon: ICON,
    render(root, ctx) {
      const ui = ctx.ui, r = ctx.report || {};
      const { el, badge, sevBadge, pill, sevColor, cssVar, trend } = ui;

      if (!r.findings) {
        root.appendChild(ui.empty("No triage run yet. Click ‘Run Triage’ to begin.",
          "<svg viewBox='0 0 24 24' width='40' height='40'><path d='M7 5l12 7-12 7V5z' fill='none' stroke='currentColor' stroke-width='1.4'/></svg>"));
        root.appendChild(el("div", { class: "center", style: { marginTop: "12px" } },
          el("button", { class: "btn btn-primary", onclick: () => GLASSBOX.runTriage(), text: "Run Triage" })));
        return;
      }

      const findings = r.findings || [];
      const rtv = findings.filter((f) => f.adversarial_verdict === "UPHELD").length;
      const confN = findings.filter((f) => f.confidence === "CONFIRMED").length;
      const infN = findings.filter((f) => f.confidence === "INFERRED").length;
      const total = findings.length || 1;
      const qN = (r.quarantined || []).length;
      const refN = (r.refuted || []).length;
      const attackN = (r.attack_coverage || []).length;
      const tacticsN = killChainTactics(r).length;
      const discN = (r.discrepancies || []).length;
      const spoliation = (r.integrity || []).some((i) => i.unchanged === false);
      const caseId = r.case_id || ctx.state.case_id || "—";

      /* ---------- 0. overview header ---------- */
      const posturePill = (label, ok) => badge(label, ok ? "good" : "bad");
      root.appendChild(el("div", { class: "ov-head rise" }, [
        el("div", {}, [
          el("div", { class: "ov-eyebrow", text: "Autonomous DFIR triage" }),
          el("h1", { class: "ov-title", text: "Incident Overview" }),
          el("div", { class: "ov-meta" }, [
            el("span", { text: "Case" }), el("code", { text: caseId }),
            el("span", { class: "sep" }),
            el("span", { text: `${(r.evidence_types || []).length} evidence types` }),
            el("span", { class: "sep" }),
            el("span", { text: `${(ctx.state.tools || []).length} read-only tools` }),
            el("span", { class: "sep" }),
            el("span", { text: `${((r.duration_ms || 0) / 1000).toFixed(2)}s` }),
          ]),
        ]),
        el("div", { class: "ov-actions" }, [
          posturePill(spoliation ? "SPOLIATION" : "Evidence intact", !spoliation),
          posturePill(r.audit_chain_valid ? "Audit valid" : "Audit broken", r.audit_chain_valid),
          el("button", { class: "btn btn-primary", onclick: () => GLASSBOX.runTriage() }, [
            el("span", { html: "<svg viewBox='0 0 24 24' width='15' height='15'><path d='M7 5l12 7-12 7V5z' fill='currentColor'/></svg>" }), "Run Triage"]),
        ]),
      ]));

      /* ---------- 1. KPI cards ---------- */
      const kpi = (opts, i) => {
        const valNode = el("div", { class: "kpi-value", text: "0" });
        countUp(valNode, opts.value);
        return el("div", { class: "card kpi lift rise", style: { "--kpi-color": opts.color, animationDelay: (60 + i * 70) + "ms" } }, [
          el("div", { class: "kpi-top" }, [
            el("div", { class: "kpi-ic", html: opts.icon }),
            el("div", { style: { flex: "1", minWidth: "0" } }, el("div", { class: "kpi-label", text: opts.label })),
            opts.badge || null,
          ]),
          valNode,
          el("div", { class: "kpi-foot" }, [el("div", { class: "fsub", text: opts.foot }), opts.trend || null]),
        ]);
      };
      root.appendChild(el("div", { class: "grid cols-4", style: { marginBottom: "18px" } }, [
        kpi({ icon: I.findings, label: "Findings", value: findings.length, color: cssVar("--brand"),
              foot: `${confN} confirmed · ${infN} inferred`, trend: trend(findings.length, { suffix: "" }) }, 0),
        kpi({ icon: I.shield, label: "Red-team verified", value: rtv, color: cssVar("--up"),
              foot: "survived adversarial panel", badge: badge(Math.round(100 * rtv / total) + "%", "good") }, 1),
        kpi({ icon: I.alert, label: "Quarantined", value: qN, color: cssVar("--med"),
              foot: "hallucinated / unsupported", badge: badge(refN + " refuted", "ghost") }, 2),
        kpi({ icon: I.grid, label: "ATT&CK techniques", value: attackN, color: cssVar("--accent"),
              foot: `${discN} cross-source discrepancies`, badge: badge(tacticsN + " tactics", "ghost") }, 3),
      ]));

      /* ---------- 2. kill-chain chart + threat posture ---------- */
      const mainRow = el("div", { class: "grid rise", style: { gridTemplateColumns: "1.6fr 1fr", gap: "18px", marginBottom: "18px", animationDelay: "340ms" } });

      // chart card
      const chartBody = el("div");
      const renderChart = (mode) => {
        chartBody.innerHTML = "";
        const data = mode === "severity" ? severitySeries(findings, sevColor) : tacticSeries(r);
        chartBody.appendChild(ui.areaChart(data.points, { height: 248, color: data.color, valueFmt: (v) => v + " findings" }));
      };
      const chartCard = el("div", { class: "card" }, [
        el("div", { class: "card-head" }, [
          el("div", { class: "sec-title" }, [el("span", { class: "si", html: I.pulse }), el("span", { text: "Kill-chain coverage" })]),
          el("div", { style: { marginLeft: "auto" } },
            ui.segmented([{ label: "By tactic", value: "tactic" }, { label: "By severity", value: "severity" }], "tactic", renderChart)),
        ]),
        el("div", { class: "card-body" }, chartBody),
      ]);
      renderChart("tactic");
      mainRow.appendChild(chartCard);

      // threat posture card
      const sevOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
      const sevCounts = {}; sevOrder.forEach((s) => sevCounts[s] = 0);
      findings.forEach((f) => sevCounts[(f.severity || "INFO").toUpperCase()]++);
      const segs = sevOrder.filter((s) => sevCounts[s]).map((s) => ({ label: s[0] + s.slice(1).toLowerCase(), value: sevCounts[s], color: sevColor(s) }));
      const donut = ui.donut(segs, { size: 132, width: 15, round: true, center: String(findings.length) });
      const legend = el("div", { class: "legend2" }, segs.map((s) => el("div", { class: "lg" }, [
        el("span", { class: "dot", style: { background: s.color } }),
        el("span", { text: s.label }),
        el("span", { class: "ct", text: String(s.value) }),
      ])));
      const metaRow = (k, v, kico) => el("div", { class: "meta-row" }, [
        el("span", { class: "k" }, kico ? [el("span", { html: kico, style: { width: "15px", height: "15px", color: "var(--faint)" } }), k] : [k]),
        (v instanceof Node ? v : el("span", { class: "v", text: v })),
      ]);
      const postureCard = el("div", { class: "card" }, [
        el("div", { class: "card-head" }, [
          el("div", { class: "sec-title" }, [el("span", { class: "si", html: I.donut }), el("span", { text: "Threat posture" })]),
        ]),
        el("div", { class: "card-body" }, [
          el("div", { class: "donut-wrap", style: { marginBottom: "8px" } }, [donut, legend]),
          el("div", { class: "hr" }),
          el("div", { class: "meta-list" }, [
            metaRow("Iterations", el("span", { class: "v mono", text: `${r.iterations_used || 0} / ${r.max_iterations || 0}` })),
            metaRow("Triage time", el("span", { class: "v mono", text: ((r.duration_ms || 0) / 1000).toFixed(2) + "s" })),
            metaRow("Integrity", badge(spoliation ? "SPOLIATION" : "INTACT", spoliation ? "bad" : "good")),
            metaRow("Audit chain", badge(r.audit_chain_valid ? "VALID" : "BROKEN", r.audit_chain_valid ? "good" : "bad")),
          ]),
          el("div", { style: { marginTop: "15px", display: "grid", gap: "8px" } }, [
            el("button", { class: "btn", style: { justifyContent: "center" }, onclick: () => ctx.go("forensic"), text: "Verify replay →" }),
            el("button", { class: "btn", style: { justifyContent: "center" }, onclick: () => ctx.go("attack"), text: "ATT&CK Navigator →" }),
          ]),
        ]),
      ]);
      mainRow.appendChild(postureCard);
      root.appendChild(mainRow);

      /* ---------- 3. findings table ---------- */
      const tableWrap = el("div");
      let q = "", sev = "ALL";
      const renderTable = () => {
        tableWrap.innerHTML = "";
        let rows = [...findings].sort((a, b) => ui.SEV.indexOf((a.severity || "INFO").toUpperCase()) - ui.SEV.indexOf((b.severity || "INFO").toUpperCase())
          || (b.confidence_score || 0) - (a.confidence_score || 0));
        if (sev !== "ALL") rows = rows.filter((f) => (f.severity || "INFO").toUpperCase() === sev);
        if (q) rows = rows.filter((f) => (f.title + " " + (f.attack || []).map((m) => m.technique_id).join(" ")).toLowerCase().includes(q.toLowerCase()));
        rows = rows.slice(0, 14);
        const cols = [
          { label: "Finding", render: (f) => el("div", { class: "row", style: { gap: "10px" } }, [
              el("span", { style: { width: "8px", height: "8px", borderRadius: "50%", background: sevColor(f.severity), flex: "0 0 auto", boxShadow: "0 0 0 3px color-mix(in srgb," + sevColor(f.severity) + " 18%, transparent)" } }),
              el("span", { style: { fontWeight: "600" }, text: f.title.length > 52 ? f.title.slice(0, 52) + "…" : f.title }) ]) },
          { label: "Severity", render: (f) => sevBadge(f.severity) },
          { label: "Confidence", render: (f) => badge(f.confidence === "CONFIRMED" ? "Confirmed" : (f.confidence === "INFERRED" ? "Inferred" : f.confidence), f.confidence === "CONFIRMED" ? "good" : "ghost") },
          { label: "ATT&CK", render: (f) => el("div", { class: "row wrap", style: { gap: "4px" } }, (f.attack || []).slice(0, 2).map((m) => pill(m.technique_id))) },
          { label: "Red-team", render: (f) => f.adversarial_verdict === "UPHELD" ? badge("VERIFIED", "good") : (f.adversarial_verdict === "DEMOTED" ? badge("demoted", "ghost") : el("span", { class: "faint", text: "—" })) },
          { label: "Confidence", render: (f) => el("div", { class: "row", style: { gap: "8px" } }, [
              scoreBar(f.confidence_score || 0, sevColor(f.severity)),
              el("span", { class: "mono", style: { fontSize: "11px", color: "var(--muted)" }, text: (f.confidence_score || 0).toFixed(2) }) ]) },
          { label: "Provenance", mono: true, render: (f) => el("span", { class: "mono faint", style: { fontSize: "11px" }, text: (f.provenance && f.provenance[0]) ? f.provenance[0].tool_exec_id : "—" }) },
        ];
        tableWrap.appendChild(rows.length ? ui.table(cols, rows) : ui.empty("No findings match"));
      };
      const tbCard = el("div", { class: "card rise", style: { animationDelay: "440ms" } }, [
        el("div", { class: "card-head" }, [
          el("div", { class: "sec-title" }, [el("span", { class: "si", html: I.table }), el("span", { text: "Findings" })]),
          el("span", { class: "sub", text: `top ${Math.min(14, findings.length)} of ${findings.length}` }),
          el("div", { class: "row", style: { marginLeft: "auto", gap: "10px" } }, [
            el("input", { class: "input", placeholder: "Search findings…", style: { width: "210px" },
              oninput: (e) => { q = e.target.value; renderTable(); } }),
            ui.segmented(["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"], "ALL", (v) => { sev = v; renderTable(); }),
          ]),
        ]),
        el("div", { class: "card-body", style: { paddingTop: "0" } }, tableWrap),
      ]);
      renderTable();
      root.appendChild(tbCard);
    },
  });

  /* helpers */
  function killChainTactics(r) {
    const set = new Set();
    (r.attack_coverage || []).forEach((m) => (m.tactic_names || []).forEach((t) => set.add(t)));
    return [...set];
  }
  function tacticSeries(r) {
    const counts = {};
    (r.findings || []).forEach((f) => (f.attack || []).forEach((m) => (m.tactic_names || []).forEach((t) => counts[t] = (counts[t] || 0) + 1)));
    const present = TACTIC_ORDER.filter((t) => counts[t]);
    const order = present.length >= 3 ? present : TACTIC_ORDER.slice(0, 6);
    return { points: order.map((t) => ({ label: t, value: counts[t] || 0 })),
             color: getComputedStyle(document.documentElement).getPropertyValue("--brand").trim() };
  }
  function severitySeries(findings, sevColor) {
    const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
    const counts = {}; order.forEach((s) => counts[s] = 0);
    findings.forEach((f) => counts[(f.severity || "INFO").toUpperCase()]++);
    return { points: order.map((s) => ({ label: s[0] + s.slice(1).toLowerCase(), value: counts[s] })), color: sevColor("HIGH") };
  }
  function scoreBar(v, color) {
    return GLASSBOX.ui.el("div", { style: { width: "54px", height: "6px", borderRadius: "4px", background: "var(--elevated)", border: "1px solid var(--border)", overflow: "hidden" } },
      GLASSBOX.ui.el("div", { style: { width: Math.round(v * 100) + "%", height: "100%", background: color } }));
  }
})();
