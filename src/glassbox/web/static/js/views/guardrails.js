/* Guardrails — architectural self-test view.
 * Runs ctx.api.guardrail() to actively probe the agent's hard boundaries for
 * bypass (write tools, path traversal, evidence RO, audit tamper, hallucination,
 * HMAC approval). These are ARCHITECTURAL constraints, not prompt-based asks —
 * the hackathon's "Constraint Implementation" criterion.
 * Contract: GLASSBOX.registerView(id, { title, sub, order, icon, badge?, render }).
 */
(function () {
  // Shield with a check — "verified boundary".
  const ICON = "<svg viewBox='0 0 24 24'><path d='M12 3l7 3v5c0 4.4-3 8.3-7 9.5C8 19.3 5 15.4 5 11V6l7-3z' fill='none' stroke='currentColor' stroke-width='1.6' stroke-linejoin='round'/><path d='M9 12l2 2 4-4' fill='none' stroke='currentColor' stroke-width='1.6' stroke-linecap='round' stroke-linejoin='round'/></svg>";

  // Friendly one-liners for each architectural check.
  const DESC = {
    NO_WRITE_TOOL:  "No write/shell tool in the MCP surface",
    PATH_TRAVERSAL: "Vault rejects path traversal",
    EVIDENCE_RO:    "Evidence resists writes (anti-spoliation)",
    AUDIT_TAMPER:   "Audit tamper is detected",
    HALLUCINATION:  "Fabricated claims are quarantined",
    HMAC_APPROVAL:  "Tampered approval tokens rejected",
  };

  GLASSBOX.registerView("guardrails", {
    title: "Guardrails", sub: "architectural boundary verification", order: 90, icon: ICON,

    async render(root, ctx) {
      const { ui } = ctx;
      const { el, card, stat, badge, empty } = ui;

      /* ---- intro card: what these checks actually are ---- */
      root.appendChild(card("Architectural Guardrails",
        el("div", { class: "muted", style: { fontSize: "13px", lineHeight: "1.55" } }, [
          el("div", {}, [
            "These are ",
            el("b", { style: { color: "var(--accent)" }, text: "architectural" }),
            " constraints — enforced by the system's structure, not by asking the model nicely. ",
            "The self-test ", el("b", { text: "actively probes each boundary for bypass" }),
            ": it tries to write to evidence, traverse the vault, tamper the audit chain, ",
            "smuggle a fabricated claim, and forge an approval token — then confirms each attempt is rejected.",
          ]),
          el("div", { class: "faint", style: { marginTop: "8px", fontSize: "12.5px" } },
            "Maps to the hackathon's Constraint Implementation criterion: a read-only agent that cannot be talked out of being read-only."),
        ]),
        { sub: "tested for bypass, not prompted" }));

      /* ---- run button + live results region ---- */
      const results = el("div", { style: { marginTop: "16px" } });
      const runBtn = el("button", { class: "btn btn-primary",
        html: ICON.replace("24 24", "24 24") + "<span>Run Guardrail Self-Test</span>" });

      const toolbar = el("div", { class: "toolbar", style: { margin: "16px 0 0" } }, [
        runBtn,
        el("span", { class: "faint", style: { fontSize: "12px" },
          text: "probes run live against the agent's tool surface and vault" }),
      ]);
      root.appendChild(toolbar);
      root.appendChild(results);

      async function run() {
        runBtn.disabled = true;
        const original = runBtn.innerHTML;
        runBtn.innerHTML = "<span class='loader'></span><span>Probing boundaries…</span>";
        results.innerHTML = "";
        let data;
        try {
          data = await ctx.api.guardrail();
        } catch (e) {
          results.appendChild(empty("Guardrail self-test unavailable: " + (e && e.message ? e.message : e)));
          runBtn.disabled = false; runBtn.innerHTML = original;
          return;
        }
        runBtn.disabled = false; runBtn.innerHTML = original;
        renderResults(data);
      }

      function renderResults(data) {
        results.innerHTML = "";
        const checks = (data && data.checks) || [];
        if (!checks.length) {
          results.appendChild(empty("No guardrail checks reported"));
          return;
        }

        const total = data.total != null ? data.total : checks.length;
        const passed = data.passed != null ? data.passed : checks.filter((c) => c.passed).length;
        const allPassed = data.all_passed != null ? data.all_passed : passed === total;

        /* ---- big summary stat ---- */
        results.appendChild(el("div", { class: "grid cols-2", style: { marginBottom: "16px" } }, [
          stat("Guardrails", passed + " / " + total + " PASSED", {
            tone: allPassed ? "good" : "bad",
            foot: allPassed ? "all architectural boundaries held" : (total - passed) + " boundary(ies) bypassable — investigate",
          }),
          stat("Verdict", allPassed ? "SECURE" : "EXPOSED", {
            tone: allPassed ? "good" : "bad",
            foot: allPassed ? "read-only contract enforced by structure" : "a constraint can be circumvented",
          }),
        ]));

        /* ---- one card per check ---- */
        const rows = checks.map((c) => {
          const ok = !!c.passed;
          const name = c.name || "UNKNOWN";
          const friendly = DESC[name] || "Architectural constraint";
          return el("div", { class: "card sev-rail " + (ok ? "low" : "crit"), style: { padding: "13px 15px" } }, [
            el("div", { class: "row", style: { justifyContent: "space-between", alignItems: "flex-start", gap: "12px" } }, [
              el("div", {}, [
                el("div", { class: "row", style: { gap: "9px", alignItems: "center" } }, [
                  badge(name, "mono"),
                  el("span", { style: { fontSize: "13px", fontWeight: "600" }, text: friendly }),
                ]),
                el("div", { class: "muted", style: { fontSize: "12.5px", marginTop: "6px", fontFamily: "var(--mono)" },
                  text: c.detail || "—" }),
              ]),
              ok ? badge("PASS", "good") : badge("FAIL", "bad"),
            ]),
          ]);
        });

        results.appendChild(card("Boundary Probes",
          el("div", { class: "grid", style: { gap: "10px" } }, rows),
          { sub: total + " checks", action: el("span", { class: "faint", style: { fontSize: "12px" },
            text: allPassed ? "every probe rejected ✓" : "review failures" }) }));
      }

      runBtn.addEventListener("click", run);

      /* auto-run once on first render */
      await run();
    },
  });
})();
