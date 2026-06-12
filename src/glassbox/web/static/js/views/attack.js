/* ATT&CK Matrix v2 — aligned kill-chain coverage board built from report.attack_coverage + findings.
 * Logic (severity index, upheld counts, tactic bucketing, kill-chain order) is unchanged & verified;
 * this is a premium visual rebuild (coverage bars, accent technique cards, consistent spacing).
 */
(function () {
  const ICON = "<svg viewBox='0 0 24 24'><path d='M3 4h18M3 9h18M3 14h18M3 19h18' fill='none' stroke='currentColor' stroke-width='1.6' stroke-linecap='round'/><path d='M8 4v15M16 4v15' fill='none' stroke='currentColor' stroke-width='1.6'/></svg>";

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

      /* ---- index findings by technique_id: severities + UPHELD count (verified logic) ---- */
      const findings = r.findings || [];
      const byTid = {};
      findings.forEach((f) => {
        const sev = (f.severity || "INFO").toUpperCase();
        const sevIdx = SEV.indexOf(sev) === -1 ? SEV.length - 1 : SEV.indexOf(sev);
        const upheld = f.adversarial_verdict === "UPHELD";
        (f.attack || []).forEach((a) => {
          const tid = a.technique_id; if (!tid) return;
          const b = byTid[tid] || (byTid[tid] = { best: SEV.length, count: 0, upheld: 0 });
          if (sevIdx < b.best) b.best = sevIdx;
          b.count += 1;
          if (upheld) b.upheld += 1;
        });
      });
      const maxSev = (tid) => { const b = byTid[tid]; return b && b.best < SEV.length ? SEV[b.best] : null; };

      /* ---- group techniques by tactic ---- */
      const byTactic = {};
      coverage.forEach((t) => {
        const tactics = (t.tactic_names && t.tactic_names.length) ? t.tactic_names : ["Uncategorized"];
        tactics.forEach((tac) => { (byTactic[tac] || (byTactic[tac] = {}))[t.technique_id] = t; });
      });
      const known = TACTIC_ORDER.filter((t) => byTactic[t]);
      const extras = Object.keys(byTactic).filter((t) => TACTIC_ORDER.indexOf(t) === -1).sort();
      const tacticCols = known.concat(extras);

      const techMapped = coverage.length;
      const tacticsCovered = tacticCols.length;
      const totalUpheld = Object.values(byTid).reduce((a, b) => a + b.upheld, 0);

      /* ---- stat row + Navigator download (download logic unchanged) ---- */
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
        } catch (e) { dlBtn.textContent = "Download failed"; }
        finally { setTimeout(() => { dlBtn.disabled = false; dlBtn.textContent = prev; }, 1600); }
      });

      root.appendChild(el("div", { class: "grid cols-4 rise", style: { marginBottom: "18px" } }, [
        stat("Techniques Mapped", fmtNum(techMapped), { tone: "accent", foot: `${fmtNum(tacticsCovered)} tactics on the kill chain` }),
        stat("Tactics Covered", `${tacticsCovered} / ${TACTIC_ORDER.length}`, { foot: "enterprise kill-chain stages" }),
        stat("Red-Team Upheld", fmtNum(totalUpheld), { tone: totalUpheld ? "good" : "", foot: "findings survived adversarial panel" }),
        el("div", { class: "card stat", style: { display: "flex", flexDirection: "column", justifyContent: "center" } }, [
          el("div", { class: "stat-label", text: "MITRE ATT&CK Navigator" }),
          el("div", { style: { marginTop: "10px" } }, dlBtn),
          el("div", { class: "stat-foot", text: "import into attack.mitre.org/navigator" }),
        ]),
      ]));

      /* ---- legend ---- */
      const legendRow = el("div", { class: "row wrap", style: { gap: "14px", marginBottom: "14px" } },
        SEV.map((s) => el("span", { class: "row", style: { gap: "6px", fontSize: "12px", color: "var(--muted)" } }, [
          el("span", { style: { width: "10px", height: "10px", borderRadius: "3px", background: sevColor(s), display: "inline-block" } }),
          s[0] + s.slice(1).toLowerCase(),
        ])));

      /* ---- the matrix grid ---- */
      const grid = el("div", { class: "atk-grid" }, tacticCols.map((tactic) => {
        const techs = Object.values(byTactic[tactic]);
        techs.sort((a, b) => {
          const sa = byTid[a.technique_id] ? byTid[a.technique_id].best : SEV.length;
          const sb = byTid[b.technique_id] ? byTid[b.technique_id].best : SEV.length;
          if (sa !== sb) return sa - sb;
          return a.technique_id.localeCompare(b.technique_id);
        });
        const techCount = techs.length;
        const activeTechs = techs.filter((t) => byTid[t.technique_id]).length;
        const cov = techCount ? Math.round((activeTechs / techCount) * 100) : 0;

        const cells = techs.map((t) => {
          const sev = maxSev(t.technique_id);
          const b = byTid[t.technique_id];
          const color = sev ? sevColor(sev) : "var(--border-hi)";
          return el("div", {
            class: "atk-cell", style: { "--cell-color": color },
            title: `${t.technique_id} · ${t.technique_name}` + (b ? ` — ${b.count} finding(s), ${b.upheld} upheld` : " — mapped (no active findings)"),
          }, [
            el("div", { class: "nm", text: t.technique_name }),
            el("div", { class: "foot" }, [
              el("span", { class: "tid", text: t.technique_id }),
              b ? el("span", { class: "row", style: { gap: "5px" } }, [
                el("span", { class: "pill", text: b.count + "×" }),
                b.upheld ? badge(b.upheld + " ✓", "good") : null,
              ].filter(Boolean)) : badge("mapped", "ghost"),
            ]),
          ]);
        });

        return el("div", { class: "atk-col" }, [
          el("div", { class: "atk-col-head" }, [
            el("div", { class: "nm" }, [el("span", { text: tactic }), el("span", { class: "ct", text: String(techCount) })]),
            el("div", { class: "atk-cov", title: `${cov}% of techniques have active findings` },
              el("i", { style: { width: cov + "%" } })),
          ]),
          el("div", { class: "atk-cells" }, cells),
        ]);
      }));

      root.appendChild(card("ATT&CK Coverage Matrix", el("div", {}, [legendRow, grid]), {
        sub: `${fmtNum(techMapped)} techniques across ${tacticsCovered} tactics`,
        action: el("button", { class: "btn btn-sm btn-ghost", text: "← Dashboard", onclick: () => ctx.go("dashboard") }),
      }));
    },
  });
})();
