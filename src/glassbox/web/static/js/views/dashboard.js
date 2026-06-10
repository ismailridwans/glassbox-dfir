/* Dashboard (overview) — the exemplar view; reference for all others.
 * Contract: GLASSBOX.registerView(id, { title, sub, order, icon, badge?, render }).
 * render(root, ctx): build DOM into `root`. ctx = { state, report, api, ui, go, refresh }.
 */
(function () {
  const ICON = "<svg viewBox='0 0 24 24'><rect x='3' y='3' width='8' height='8' rx='2' fill='none' stroke='currentColor' stroke-width='1.6'/><rect x='13' y='3' width='8' height='5' rx='2' fill='none' stroke='currentColor' stroke-width='1.6'/><rect x='13' y='11' width='8' height='10' rx='2' fill='none' stroke='currentColor' stroke-width='1.6'/><rect x='3' y='13' width='8' height='8' rx='2' fill='none' stroke='currentColor' stroke-width='1.6'/></svg>";

  GLASSBOX.registerView("dashboard", {
    title: "Dashboard", sub: "incident overview", order: 10, icon: ICON,
    render(root, ctx) {
      const { ui, report: r } = ctx;
      const { el, card, stat, donut, legend, bars, sevColor, sevBadge, badge } = ui;

      if (!r || !r.findings) {
        root.appendChild(ui.empty("No triage run yet. Click ‘Run Triage’ to begin.",
          "<svg viewBox='0 0 24 24' width='40' height='40'><path d='M7 5l12 7-12 7V5z' fill='none' stroke='currentColor' stroke-width='1.4'/></svg>"));
        const b = el("div", { class: "center", style: { marginTop: "10px" } },
          el("button", { class: "btn btn-primary", onclick: () => GLASSBOX.runTriage(), text: "Run Triage" }));
        root.appendChild(b); return;
      }

      const findings = r.findings || [];
      const rtv = findings.filter((f) => f.adversarial_verdict === "UPHELD").length;
      const sevCounts = {};
      ui.SEV.forEach((s) => sevCounts[s] = 0);
      findings.forEach((f) => { sevCounts[(f.severity || "INFO").toUpperCase()] = (sevCounts[(f.severity||"INFO").toUpperCase()]||0) + 1; });
      const spoliation = (r.integrity || []).some((i) => i.unchanged === false);

      /* ---- top metric cards (fintech-style with sparkbars) ---- */
      const confN = findings.filter(f=>f.confidence==='CONFIRMED').length;
      const infN = findings.filter(f=>f.confidence==='INFERRED').length;
      const cssv = (n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
      const metric = (icon, name, sub, value, filled, color, foot) => el("div", { class: "card metric lift" }, [
        el("div", { class: "metric-top" }, [
          el("div", { class: "metric-ic", html: icon, style: color ? { background: "color-mix(in srgb,"+color+" 16%,transparent)", color } : null }),
          el("div", {}, [ el("div", { class: "metric-name", text: name }), el("div", { class: "metric-sub", text: sub }) ]),
        ]),
        el("div", { class: "metric-value", text: value, style: color ? { color } : null }),
        el("div", { class: "metric-spark" }, ui.sparkbars(28, filled, color || cssv("--brand"))),
        foot ? el("div", { class: "metric-sub", style: { marginTop: "8px" }, html: foot }) : null,
      ]);
      const total = findings.length || 1;
      root.appendChild(el("div", { class: "grid cols-4", style: { marginBottom: "16px" } }, [
        metric("<svg viewBox='0 0 24 24' width='18' height='18'><path d='M4 6h16M4 12h10M4 18h7' stroke='currentColor' stroke-width='1.8' stroke-linecap='round'/></svg>",
          "Findings", "grounded + verified", String(findings.length), 28, cssv("--brand"),
          `${confN} confirmed · ${infN} inferred`),
        metric("<svg viewBox='0 0 24 24' width='18' height='18'><path d='M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z' fill='none' stroke='currentColor' stroke-width='1.7' stroke-linejoin='round'/><path d='M9 12l2 2 4-4' stroke='currentColor' stroke-width='1.7' stroke-linecap='round' stroke-linejoin='round'/></svg>",
          "Red-Team Verified", "survived adversarial panel", String(rtv), Math.round(28*rtv/total), cssv("--up"),
          `${Math.round(100*rtv/total)}% of findings upheld`),
        metric("<svg viewBox='0 0 24 24' width='18' height='18'><path d='M12 3l9 16H3z' fill='none' stroke='currentColor' stroke-width='1.7' stroke-linejoin='round'/><path d='M12 9v4M12 16.5v.5' stroke='currentColor' stroke-width='1.8' stroke-linecap='round'/></svg>",
          "Quarantined", "hallucinated / unsupported", String((r.quarantined||[]).length), Math.max(1,(r.quarantined||[]).length), cssv("--med"),
          `${(r.refuted||[]).length} also refuted by red-team`),
        metric("<svg viewBox='0 0 24 24' width='18' height='18'><rect x='3' y='3' width='7' height='7' rx='1.5' fill='none' stroke='currentColor' stroke-width='1.7'/><rect x='14' y='3' width='7' height='7' rx='1.5' fill='none' stroke='currentColor' stroke-width='1.7'/><rect x='3' y='14' width='7' height='7' rx='1.5' fill='none' stroke='currentColor' stroke-width='1.7'/><rect x='14' y='14' width='7' height='7' rx='1.5' fill='none' stroke='currentColor' stroke-width='1.7'/></svg>",
          "ATT&CK", "kill-chain coverage", String((r.attack_coverage||[]).length), Math.min(28,(r.attack_coverage||[]).length), cssv("--low"),
          `${(r.discrepancies||[]).length} cross-source discrepancies`),
      ]));

      /* ---- integrity + speed banner ---- */
      const banner = el("div", { class: "grid cols-3", style: { marginBottom: "16px" } }, [
        card("Evidence Integrity", el("div", { class: "row", style: { gap: "14px" } }, [
          el("div", { class: "stat-value", style: { fontSize: "22px", color: spoliation ? "var(--bad)" : "var(--good)" },
            text: spoliation ? "SPOLIATION" : "INTACT" }),
          el("div", { class: "muted", style: { fontSize: "12.5px" },
            html: `${(r.integrity||[]).length} file(s) hashed<br>SHA-256 before == after` }),
        ]), { sub: "anti-spoliation" }),
        card("Audit Chain", el("div", { class: "row", style: { gap: "14px" } }, [
          el("div", { class: "stat-value", style: { fontSize: "22px", color: r.audit_chain_valid ? "var(--good)" : "var(--bad)" },
            text: r.audit_chain_valid ? "VALID" : "BROKEN" }),
          el("div", { class: "muted", style: { fontSize: "12.5px" }, html: "hash-chained<br>tamper-evident" }),
        ]), { sub: "chain of custody" }),
        card("Machine Speed", el("div", { class: "row", style: { gap: "14px" } }, [
          el("div", { class: "stat-value", style: { fontSize: "22px", color: "var(--accent)" },
            text: ((r.duration_ms||0)/1000).toFixed(2) + "s" }),
          el("div", { class: "muted", style: { fontSize: "12.5px" },
            html: `${r.iterations_used||0}/${r.max_iterations||0} self-correction iters<br><span class='faint'>adversary breakout: 7 min</span>` }),
        ]), { sub: "triage time" }),
      ]);
      root.appendChild(banner);

      /* ---- charts row ---- */
      const segs = ui.SEV.map((s) => ({ label: s[0] + s.slice(1).toLowerCase(), value: sevCounts[s], color: sevColor(s) }));
      const sevCard = card("Severity Breakdown",
        el("div", { class: "center" }, [ donut(segs, { center: String(findings.length), round: true }), legend(segs) ]),
        { sub: `${findings.length} findings` });

      // tactic coverage bars
      const tacticCount = {};
      (r.attack_coverage || []).forEach((m) => (m.tactic_names || []).forEach((t) => tacticCount[t] = (tacticCount[t]||0)+1));
      const tItems = Object.entries(tacticCount).sort((a,b)=>b[1]-a[1]).slice(0, 8)
        .map(([label, value]) => ({ label, value }));
      const tacticCard = card("ATT&CK Tactic Coverage",
        tItems.length ? bars(tItems) : ui.empty("No techniques mapped"),
        { sub: `${Object.keys(tacticCount).length} tactics`, action: el("button", { class: "btn btn-sm btn-ghost", text: "Matrix →", onclick: () => ctx.go("attack") }) });

      root.appendChild(el("div", { class: "grid cols-2", style: { marginBottom: "16px" } }, [sevCard, tacticCard]));

      /* ---- top findings ---- */
      const top = [...findings].sort((a, b) => ui.SEV.indexOf((a.severity||"INFO").toUpperCase()) - ui.SEV.indexOf((b.severity||"INFO").toUpperCase())).slice(0, 6);
      const list = el("div", { class: "grid", style: { gap: "10px" } }, top.map((f) => {
        const k = ui.sevKey(f.severity);
        return el("div", { class: "card sev-rail " + k, style: { padding: "12px 14px" } }, [
          el("div", { class: "row", style: { justifyContent: "space-between" } }, [
            el("b", { text: f.title }),
            el("div", { class: "row", style: { gap: "6px" } }, [
              f.adversarial_verdict === "UPHELD" ? badge("RED-TEAM ✓", "good") : null,
              sevBadge(f.severity),
            ]),
          ]),
          (f.attack && f.attack.length) ? el("div", { style: { marginTop: "6px" } },
            f.attack.slice(0, 4).map((m) => ui.pill(m.technique_id))) : null,
        ]);
      }));
      root.appendChild(card("Top Findings", top.length ? list : ui.empty("No findings"),
        { sub: "by severity", action: el("button", { class: "btn btn-sm btn-ghost", text: "All findings →", onclick: () => ctx.go("findings") }) }));
    },
  });
})();
