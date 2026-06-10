/* ATT&CK Matrix — kill-chain coverage built from report.attack_coverage + findings.
 * Contract: GLASSBOX.registerView(id, { title, sub, order, icon, badge?, render }).
 * render(root, ctx): build DOM into `root`. ctx = { state, report, api, ui, go, refresh }.
 */
(function () {
  const ICON = "<svg viewBox='0 0 24 24'><path d='M3 4h18M3 9h18M3 14h18M3 19h18' fill='none' stroke='currentColor' stroke-width='1.6' stroke-linecap='round'/><path d='M8 4v15M16 4v15' fill='none' stroke='currentColor' stroke-width='1.6'/></svg>";

  /* MITRE kill-chain tactic order (enterprise). */
  const TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
  ];

  GLASSBOX.registerView("attack", {
    title: "ATT&CK Matrix", sub: "kill-chain coverage", order: 50, icon: ICON,
    badge: (ctx) => (ctx.report && ctx.report.attack_coverage || []).length || null,

    async render(root, ctx) {
      const { ui, report: r } = ctx;
      const { el, card, stat, badge, sevColor, sevKey, SEV, fmtNum, empty } = ui;

      if (!r || !r.findings) { root.appendChild(empty("Run triage first")); return; }

      const coverage = r.attack_coverage || [];
      if (!coverage.length) {
        root.appendChild(empty("No ATT&CK techniques mapped",
          "<svg viewBox='0 0 24 24' width='40' height='40'><path d='M3 5h18M3 12h18M3 19h18' fill='none' stroke='currentColor' stroke-width='1.4' stroke-linecap='round'/></svg>"));
        return;
      }

      /* ---- index findings by technique_id: collect severities + UPHELD count ---- */
      const findings = r.findings || [];
      const byTid = {};   // tid -> { sevs:[idx...], count, upheld }
      findings.forEach((f) => {
        const sev = (f.severity || "INFO").toUpperCase();
        const sevIdx = SEV.indexOf(sev) === -1 ? SEV.length - 1 : SEV.indexOf(sev);
        const upheld = f.adversarial_verdict === "UPHELD";
        (f.attack || []).forEach((a) => {
          const tid = a.technique_id;
          if (!tid) return;
          const b = byTid[tid] || (byTid[tid] = { best: SEV.length, count: 0, upheld: 0 });
          if (sevIdx < b.best) b.best = sevIdx;   // lower idx == higher severity
          b.count += 1;
          if (upheld) b.upheld += 1;
        });
      });
      const maxSev = (tid) => { const b = byTid[tid]; return b && b.best < SEV.length ? SEV[b.best] : null; };

      /* ---- group techniques by tactic (a technique can span multiple tactics) ---- */
      const byTactic = {};   // tactic -> { tid: technique }
      coverage.forEach((t) => {
        const tactics = (t.tactic_names && t.tactic_names.length) ? t.tactic_names : ["Uncategorized"];
        tactics.forEach((tac) => {
          const bucket = byTactic[tac] || (byTactic[tac] = {});
          if (!bucket[t.technique_id]) bucket[t.technique_id] = t;
        });
      });

      /* kill-chain order first, then any extras (e.g. Uncategorized) alphabetically. */
      const known = TACTIC_ORDER.filter((t) => byTactic[t]);
      const extras = Object.keys(byTactic).filter((t) => TACTIC_ORDER.indexOf(t) === -1).sort();
      const tacticCols = known.concat(extras);

      const techMapped = coverage.length;
      const tacticsCovered = tacticCols.length;
      const totalUpheld = Object.values(byTid).reduce((a, b) => a + b.upheld, 0);

      /* ---- top stat row + Navigator download ---- */
      const dlBtn = el("button", { class: "btn btn-sm btn-primary", text: "Download Navigator Layer" });
      dlBtn.addEventListener("click", async () => {
        const prev = dlBtn.textContent;
        dlBtn.disabled = true; dlBtn.textContent = "Building…";
        try {
          const layer = await ctx.api.navigator();
          const blob = new Blob([JSON.stringify(layer, null, 2)], { type: "application/json" });
          const url = URL.createObjectURL(blob);
          const a = el("a", { href: url, download: "glassbox_navigator_layer.json" });
          document.body.appendChild(a); a.click(); a.remove();
          setTimeout(() => URL.revokeObjectURL(url), 1000);
          dlBtn.textContent = "Downloaded ✓";
        } catch (e) {
          dlBtn.textContent = "Download failed";
        } finally {
          setTimeout(() => { dlBtn.disabled = false; dlBtn.textContent = prev; }, 1600);
        }
      });

      root.appendChild(el("div", { class: "grid cols-4", style: { marginBottom: "16px" } }, [
        stat("Techniques Mapped", fmtNum(techMapped), { tone: "accent", foot: `${fmtNum(tacticsCovered)} tactics on the kill chain` }),
        stat("Tactics Covered", `${tacticsCovered} / ${TACTIC_ORDER.length}`, { foot: "enterprise kill-chain stages" }),
        stat("Red-Team Upheld", fmtNum(totalUpheld), { tone: totalUpheld ? "good" : "", foot: "findings survived adversarial panel" }),
        el("div", { class: "card stat", style: { justifyContent: "center" } }, [
          el("div", { class: "stat-label", text: "MITRE ATT&CK Navigator" }),
          el("div", { style: { marginTop: "8px" } }, dlBtn),
          el("div", { class: "stat-foot", text: "import into attack.mitre.org/navigator" }),
        ]),
      ]));

      /* ---- severity legend ---- */
      const legendRow = el("div", { class: "row wrap", style: { gap: "12px", marginBottom: "12px" } },
        SEV.map((s) => el("span", { class: "row", style: { gap: "6px", fontSize: "12px", color: "var(--muted)" } }, [
          el("span", { style: { width: "10px", height: "10px", borderRadius: "3px", background: sevColor(s), display: "inline-block" } }),
          s[0] + s.slice(1).toLowerCase(),
        ])));

      /* ---- the matrix grid ---- */
      const grid = el("div", { class: "attack-grid" }, tacticCols.map((tactic) => {
        const techs = Object.values(byTactic[tactic]);
        // sort techniques in a column by max severity (most severe first), then id
        techs.sort((a, b) => {
          const sa = byTid[a.technique_id] ? byTid[a.technique_id].best : SEV.length;
          const sb = byTid[b.technique_id] ? byTid[b.technique_id].best : SEV.length;
          if (sa !== sb) return sa - sb;
          return a.technique_id.localeCompare(b.technique_id);
        });

        const cells = techs.map((t) => {
          const sev = maxSev(t.technique_id);
          const b = byTid[t.technique_id];
          const color = sev ? sevColor(sev) : "var(--border)";
          const cell = el("div", {
            class: "tech-cell" + (sev ? " sev-rail " + sevKey(sev) : ""),
            style: { borderLeft: "3px solid " + color },
            title: `${t.technique_id} · ${t.technique_name}` + (b ? ` — ${b.count} finding(s), ${b.upheld} upheld` : " — no active findings"),
          }, [
            el("div", { text: t.technique_name, style: { fontWeight: "600", lineHeight: "1.3" } }),
            el("div", { class: "row", style: { justifyContent: "space-between", marginTop: "4px", alignItems: "center" } }, [
              el("span", { class: "tid", text: t.technique_id }),
              b ? el("span", { class: "row", style: { gap: "5px" } }, [
                el("span", { class: "pill", text: b.count + "×" }),
                b.upheld ? badge(b.upheld + " ✓", "good") : null,
              ]) : badge("mapped", "ghost"),
            ]),
          ]);
          return cell;
        });

        const techCount = techs.length;
        return el("div", { class: "tactic-col" }, [
          el("div", { class: "tactic-head row", style: { justifyContent: "space-between", alignItems: "center" } }, [
            el("span", { text: tactic }),
            el("span", { class: "tid", style: { color: "#7d93b8" }, text: String(techCount) }),
          ]),
          ...cells,
        ]);
      }));

      root.appendChild(card("ATT&CK Coverage Matrix", el("div", {}, [legendRow, grid]), {
        sub: `${fmtNum(techMapped)} techniques across ${tacticsCovered} tactics`,
        action: el("button", { class: "btn btn-sm btn-ghost", text: "← Dashboard", onclick: () => ctx.go("dashboard") }),
      }));
    },
  });
})();
