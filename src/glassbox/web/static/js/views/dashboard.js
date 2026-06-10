/* Dashboard — fintech-grade layout: metric cards → interactive chart + control panel → findings table. */
(function () {
  const ICON = "<svg viewBox='0 0 24 24'><rect x='3' y='3' width='8' height='8' rx='2' fill='none' stroke='currentColor' stroke-width='1.6'/><rect x='13' y='3' width='8' height='5' rx='2' fill='none' stroke='currentColor' stroke-width='1.6'/><rect x='13' y='11' width='8' height='10' rx='2' fill='none' stroke='currentColor' stroke-width='1.6'/><rect x='3' y='13' width='8' height='8' rx='2' fill='none' stroke='currentColor' stroke-width='1.6'/></svg>";

  const TACTIC_ORDER = ["Reconnaissance","Resource Development","Initial Access","Execution",
    "Persistence","Privilege Escalation","Defense Evasion","Credential Access","Discovery",
    "Lateral Movement","Collection","Command and Control","Exfiltration","Impact"];

  GLASSBOX.registerView("dashboard", {
    title: "Dashboard", sub: "incident overview", order: 10, icon: ICON,
    render(root, ctx) {
      const ui = ctx.ui, r = ctx.report || {};
      const { el, card, badge, sevBadge, pill, sevKey, sevColor, cssVar, trend } = ui;

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
      const spoliation = (r.integrity || []).some((i) => i.unchanged === false);

      /* ---------- 1. metric cards ---------- */
      const metric = (icon, name, value, sub, pillNode, filled, color) => el("div", { class: "card metric lift" }, [
        el("div", { class: "metric-top" }, [
          el("div", { class: "metric-ic", html: icon, style: color ? { background: "color-mix(in srgb," + color + " 16%,transparent)", color } : null }),
          el("div", { style: { flex: "1" } }, [ el("div", { class: "metric-name", text: name }), el("div", { class: "metric-sub", text: sub }) ]),
          pillNode || null,
        ]),
        el("div", { class: "metric-value", text: value, style: color ? { color } : null }),
        el("div", { class: "metric-spark" }, ui.sparkbars(28, filled, color || cssVar("--brand"))),
      ]);
      root.appendChild(el("div", { class: "grid cols-4", style: { marginBottom: "16px" } }, [
        metric("<svg viewBox='0 0 24 24' width='18' height='18'><path d='M4 6h16M4 12h10M4 18h7' stroke='currentColor' stroke-width='1.8' stroke-linecap='round'/></svg>",
          "Findings", String(findings.length), `${confN} confirmed · ${infN} inferred`,
          trend(findings.length, { suffix: " run" }), 28, cssVar("--brand")),
        metric("<svg viewBox='0 0 24 24' width='18' height='18'><path d='M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z' fill='none' stroke='currentColor' stroke-width='1.7' stroke-linejoin='round'/><path d='M9 12l2 2 4-4' stroke='currentColor' stroke-width='1.7' stroke-linecap='round' stroke-linejoin='round'/></svg>",
          "Red-Team Verified", String(rtv), "survived adversarial panel",
          badge(Math.round(100 * rtv / total) + "%", "good"), Math.round(28 * rtv / total), cssVar("--up")),
        metric("<svg viewBox='0 0 24 24' width='18' height='18'><path d='M12 3l9 16H3z' fill='none' stroke='currentColor' stroke-width='1.7' stroke-linejoin='round'/><path d='M12 9v4M12 16.5v.5' stroke='currentColor' stroke-width='1.8' stroke-linecap='round'/></svg>",
          "Quarantined", String((r.quarantined || []).length), "hallucinated / unsupported",
          badge((r.refuted || []).length + " refuted", "ghost"), Math.max(1, (r.quarantined || []).length), cssVar("--med")),
        metric("<svg viewBox='0 0 24 24' width='18' height='18'><rect x='3' y='3' width='7' height='7' rx='1.5' fill='none' stroke='currentColor' stroke-width='1.7'/><rect x='14' y='3' width='7' height='7' rx='1.5' fill='none' stroke='currentColor' stroke-width='1.7'/><rect x='3' y='14' width='7' height='7' rx='1.5' fill='none' stroke='currentColor' stroke-width='1.7'/><rect x='14' y='14' width='7' height='7' rx='1.5' fill='none' stroke='currentColor' stroke-width='1.7'/></svg>",
          "ATT&CK", String((r.attack_coverage || []).length), `${(r.discrepancies || []).length} discrepancies`,
          badge(killChainTactics(r).length + " tactics", "ghost"), Math.min(28, (r.attack_coverage || []).length), cssVar("--low")),
      ]));

      /* ---------- 2. chart + control panel ---------- */
      const mainRow = el("div", { class: "grid", style: { gridTemplateColumns: "1.7fr 1fr", gap: "16px", marginBottom: "16px" } });

      // chart card
      const chartBody = el("div");
      const renderChart = (mode) => {
        chartBody.innerHTML = "";
        const data = mode === "severity" ? severitySeries(findings, sevColor) : tacticSeries(r);
        chartBody.appendChild(ui.areaChart(data.points, { height: 250, color: data.color, valueFmt: (v) => v + " findings" }));
      };
      const chartHead = el("div", { class: "card-head" }, [
        el("div", {}, [
          el("h3", { text: "Kill-chain coverage" }),
          el("div", { class: "muted", style: { fontSize: "12px", marginTop: "2px" } }, [
            el("b", { class: "mono", style: { fontSize: "20px", color: "var(--text)" }, text: String(findings.length) }),
            "  findings  ", trend(findings.length, { suffix: " this run" }),
          ]),
        ]),
        el("div", { style: { marginLeft: "auto" } },
          ui.segmented([{ label: "By tactic", value: "tactic" }, { label: "By severity", value: "severity" }], "tactic", renderChart)),
      ]);
      const chartCard = el("div", { class: "card" }, [chartHead, el("div", { class: "card-body" }, chartBody)]);
      renderChart("tactic");
      mainRow.appendChild(chartCard);

      // control panel
      const evChips = el("div", { class: "row wrap", style: { gap: "5px" } },
        (r.evidence_types || []).map((t) => badge(t, "ghost")));
      const kv = (k, v) => el("div", { class: "row", style: { justifyContent: "space-between", padding: "9px 0", borderBottom: "1px solid var(--border)", fontSize: "13px" } },
        [el("span", { class: "muted", text: k }), (v instanceof Node ? v : el("b", { text: v }))]);
      const panel = el("div", { class: "card" }, [
        el("div", { class: "card-head" }, [
          el("div", { class: "metric-ic", style: { width: "30px", height: "30px" }, html: "<svg viewBox='0 0 24 24' width='17' height='17'><path d='M12 3v18M3 12h18' stroke='currentColor' stroke-width='1.7' stroke-linecap='round'/><circle cx='12' cy='12' r='9' fill='none' stroke='currentColor' stroke-width='1.4'/></svg>" }),
          el("h3", { text: "Triage Control" }),
        ]),
        el("div", { class: "card-body" }, [
          kv("Case", el("b", { class: "mono", style: { fontSize: "12px" }, text: r.case_id || ctx.state.case_id })),
          kv("Evidence", evChips),
          kv("Iterations", `${r.iterations_used || 0} / ${r.max_iterations || 0}`),
          kv("Triage time", el("b", { class: "mono", text: ((r.duration_ms || 0) / 1000).toFixed(2) + "s" })),
          kv("Integrity", badge(spoliation ? "SPOLIATION" : "INTACT", spoliation ? "bad" : "good")),
          kv("Audit chain", badge(r.audit_chain_valid ? "VALID" : "BROKEN", r.audit_chain_valid ? "good" : "bad")),
          el("div", { style: { marginTop: "16px", display: "grid", gap: "9px" } }, [
            el("button", { class: "btn btn-primary", style: { justifyContent: "center" }, onclick: () => GLASSBOX.runTriage() }, [
              el("span", { html: "<svg viewBox='0 0 24 24' width='15' height='15'><path d='M7 5l12 7-12 7V5z' fill='currentColor'/></svg>" }), "Run Triage"]),
            el("button", { class: "btn", style: { justifyContent: "center" }, onclick: () => ctx.go("forensic"), text: "Verify replay →" }),
            el("button", { class: "btn", style: { justifyContent: "center" }, onclick: () => ctx.go("attack"), text: "ATT&CK Navigator →" }),
          ]),
        ]),
      ]);
      mainRow.appendChild(panel);
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
          { label: "Finding", render: (f) => el("div", { class: "row", style: { gap: "9px" } }, [
              el("span", { style: { width: "8px", height: "8px", borderRadius: "50%", background: sevColor(f.severity), flex: "0 0 auto" } }),
              el("span", { style: { fontWeight: "600" }, text: f.title.length > 52 ? f.title.slice(0, 52) + "…" : f.title }) ]) },
          { label: "Severity", render: (f) => sevBadge(f.severity) },
          { label: "Confidence", render: (f) => badge(f.confidence === "CONFIRMED" ? "Confirmed" : (f.confidence === "INFERRED" ? "Inferred" : f.confidence), f.confidence === "CONFIRMED" ? "good" : "ghost") },
          { label: "ATT&CK", render: (f) => el("div", { class: "row wrap", style: { gap: "4px" } }, (f.attack || []).slice(0, 2).map((m) => pill(m.technique_id))) },
          { label: "Red-team", render: (f) => f.adversarial_verdict === "UPHELD" ? badge("VERIFIED", "good") : (f.adversarial_verdict === "DEMOTED" ? badge("demoted", "ghost") : el("span", { class: "faint", text: "—" })) },
          { label: "Confidence score", render: (f) => el("div", { class: "row", style: { gap: "8px" } }, [
              scoreBar(f.confidence_score || 0, sevColor(f.severity)),
              el("span", { class: "mono", style: { fontSize: "11px", color: "var(--muted)" }, text: (f.confidence_score || 0).toFixed(2) }) ]) },
          { label: "Provenance", mono: true, render: (f) => el("span", { class: "mono faint", style: { fontSize: "11px" }, text: (f.provenance && f.provenance[0]) ? f.provenance[0].tool_exec_id : "—" }) },
        ];
        tableWrap.appendChild(rows.length ? ui.table(cols, rows) : ui.empty("No findings match"));
      };
      const tbCard = el("div", { class: "card" }, [
        el("div", { class: "card-head" }, [
          el("h3", { text: "Findings" }),
          el("span", { class: "sub", text: `top ${Math.min(14, findings.length)} of ${findings.length}` }),
          el("div", { class: "row", style: { marginLeft: "auto", gap: "10px" } }, [
            el("input", { class: "input", placeholder: "Search findings…", style: { width: "200px" },
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
