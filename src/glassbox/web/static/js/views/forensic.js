/* Forensic & Replay — court-admissibility, evidence integrity, deterministic
 * replay, and the Diamond Model of intrusion analysis.
 * Contract: GLASSBOX.registerView(id, { title, sub, order, icon, badge?, render }).
 * render(root, ctx): build DOM into `root`. ctx = { state, report, api, ui, go, refresh }.
 */
(function () {
  // Shield-with-check: integrity / chain-of-custody motif.
  const ICON = "<svg viewBox='0 0 24 24'><path d='M12 3l7 3v5c0 4.6-3 8.3-7 9.5C8 19.3 5 15.6 5 11V6l7-3z' fill='none' stroke='currentColor' stroke-width='1.6' stroke-linejoin='round'/><path d='M9 12l2 2 4-4.5' fill='none' stroke='currentColor' stroke-width='1.6' stroke-linecap='round' stroke-linejoin='round'/></svg>";

  const basename = (p) => String(p || "").split(/[\\/]/).pop() || String(p || "");
  const trunc = (h, head = 10, tail = 6) => {
    const s = String(h || "");
    if (s.length <= head + tail + 1) return s || "—";
    return s.slice(0, head) + "…" + s.slice(-tail);
  };

  GLASSBOX.registerView("forensic", {
    title: "Forensic & Replay", sub: "court-admissibility & reproducibility", order: 100, icon: ICON,
    badge: (ctx) => (ctx.report && ctx.report.integrity ? ctx.report.integrity.length : null),

    async render(root, ctx) {
      const { ui, report: r } = ctx;
      const { el, card, stat, badge, pill, table, empty } = ui;

      if (!r || !r.findings) { root.appendChild(empty("Run triage first")); return; }

      /* ============================================================
       * (1) Deterministic Replay
       * ============================================================ */
      const replayBody = el("div", { class: "grid", style: { gap: "14px" } });

      const verdictWrap = el("div", { class: "center" }, [
        el("div", { class: "muted", style: { fontSize: "12.5px" },
          text: "Press verify to re-derive the full finding set from the audit log + captured tool output." }),
      ]);
      const resultSlot = el("div");

      const runReplay = async () => {
        verifyBtn.disabled = true;
        verdictWrap.innerHTML = "";
        verdictWrap.appendChild(el("div", { class: "center", style: { padding: "12px" } }, el("span", { class: "loader" })));
        resultSlot.innerHTML = "";
        let rep;
        try { rep = await ctx.api.replay(); }
        catch (e) { rep = null; }
        verifyBtn.disabled = false;
        verdictWrap.innerHTML = "";

        if (!rep) {
          verdictWrap.appendChild(empty("Replay endpoint unavailable"));
          return;
        }

        const ok = rep.reproducible === true;
        const checked = rep.findings_checked || 0;
        const reproduced = rep.findings_reproduced || 0;

        verdictWrap.appendChild(el("div", { class: "center" }, [
          el("div", {
            style: {
              fontSize: "46px", fontWeight: "800", lineHeight: "1", letterSpacing: ".02em",
              fontFamily: "var(--mono)", color: ok ? "var(--good)" : "var(--bad)",
            },
            text: ok ? "YES" : "NO",
          }),
          el("div", { class: "faint", style: { fontSize: "12px", marginTop: "6px", textTransform: "uppercase", letterSpacing: ".1em" },
            text: "reproducible" }),
        ]));

        resultSlot.appendChild(el("div", { class: "grid cols-3", style: { gap: "12px", marginTop: "14px" } }, [
          stat("Findings Reproduced", `${reproduced}/${checked}`, {
            tone: ok ? "good" : (reproduced ? "warn" : "bad"),
            foot: "re-derived from raw tool output",
          }),
          stat("Audit Chain", rep.audit_chain_valid ? "VALID" : "BROKEN", {
            tone: rep.audit_chain_valid ? "good" : "bad",
            foot: "hash-chained, tamper-evident",
          }),
          stat("Failed", ui.fmtNum(rep.failed || 0), {
            tone: (rep.failed || 0) ? "bad" : "good",
            foot: "findings that did not re-derive",
          }),
        ]));
      };

      const verifyBtn = el("button", { class: "btn btn-primary", onclick: runReplay, text: "Verify Reproducibility" });

      replayBody.appendChild(el("div", { class: "row", style: { justifyContent: "center" } }, verifyBtn));
      replayBody.appendChild(verdictWrap);
      replayBody.appendChild(resultSlot);
      replayBody.appendChild(el("div", {
        class: "muted", style: { fontSize: "12.5px", lineHeight: "1.55", marginTop: "4px" },
        html: "Reproducibility is GLASSBOX's <b>known error rate</b> — a different examiner, given only the "
          + "audit log and captured tool output, re-derives the same finding set without re-touching the evidence. "
          + "This satisfies the <i>Daubert</i> standard's testability / known-error-rate prong (FRE 702).",
      }));

      root.appendChild(card("Deterministic Replay", replayBody, { sub: "Daubert · known error rate" }));

      /* ============================================================
       * (2) Evidence Integrity
       * ============================================================ */
      const integrity = r.integrity || [];
      const spoliation = integrity.some((i) => i.unchanged === false);

      const integHead = el("div", { class: "row", style: { gap: "10px", marginBottom: "12px" } }, [
        el("span", { class: "faint", style: { fontSize: "12px", textTransform: "uppercase", letterSpacing: ".08em" }, text: "Spoliation" }),
        badge(spoliation ? "YES" : "NO", spoliation ? "bad" : "good"),
        el("span", { class: "faint", style: { fontSize: "12px", marginLeft: "auto" },
          text: `${integrity.length} evidence file(s) · SHA-256 before vs after` }),
      ]);

      let integBody;
      if (!integrity.length) {
        integBody = empty("No integrity records");
      } else {
        const cols = [
          { label: "File", render: (row) => el("span", { class: "mono", text: basename(row.path) }) },
          { label: "SHA-256 before", mono: true, render: (row) => trunc(row.sha256_before) },
          { label: "SHA-256 after", mono: true, render: (row) => trunc(row.sha256_after) },
          { label: "Status", render: (row) => row.unchanged === false ? badge("CHANGED", "bad") : badge("UNCHANGED", "good") },
        ];
        integBody = table(cols, integrity);
      }

      root.appendChild(card("Evidence Integrity",
        el("div", {}, [integHead, integBody]),
        { sub: "anti-spoliation · read-only triage" }));

      /* ============================================================
       * (3) Diamond Model of Intrusion Analysis
       * ============================================================ */
      let dm = null;
      try { dm = await ctx.api.diamond(); } catch (e) { dm = null; }

      let diamondBody;
      if (!dm) {
        diamondBody = empty("Diamond model unavailable");
      } else {
        const cap = dm.capability || {};
        const infra = dm.infrastructure || {};
        const vic = dm.victim || {};
        const adv = dm.adversary || {};

        const techniques = cap.attack_techniques || [];
        const artifacts = cap.malware_artifacts || [];
        const c2 = infra.c2_and_network_iocs || [];
        const hosts = vic.hosts || [];

        const vertex = (label, accent, body) =>
          el("div", { class: "card", style: { padding: "0" } }, [
            el("div", { class: "card-head", style: { padding: "10px 14px" } }, [
              el("span", { style: { width: "8px", height: "8px", borderRadius: "2px", background: accent, display: "inline-block" } }),
              el("h3", { text: label }),
            ]),
            el("div", { class: "card-body", style: { padding: "13px 14px" } }, body),
          ]);

        const kv = (label, value, mono) => el("div", { style: { marginBottom: "8px" } }, [
          el("div", { class: "faint", style: { fontSize: "11px", textTransform: "uppercase", letterSpacing: ".07em", marginBottom: "3px" }, text: label }),
          el("div", { class: mono ? "mono" : "muted", style: { fontSize: "12.5px", lineHeight: "1.5", wordBreak: "break-word" }, text: value }),
        ]);

        // Adversary
        const advBody = adv.assessment
          ? el("div", {}, [
              el("div", { class: "muted", style: { fontSize: "12.5px", lineHeight: "1.55" }, text: adv.assessment }),
              adv.techniques_observed != null
                ? el("div", { class: "faint", style: { fontSize: "12px", marginTop: "8px" },
                    text: `${adv.techniques_observed} techniques observed (no actor attribution)` })
                : null,
            ])
          : empty("Unattributed");

        // Capability: techniques as pills + malware artifacts
        const capBody = el("div", {}, [
          techniques.length
            ? el("div", { class: "row wrap", style: { gap: "5px", marginBottom: artifacts.length ? "12px" : "0" } },
                techniques.map((t) => pill(t)))
            : el("div", { class: "faint", style: { fontSize: "12px", marginBottom: artifacts.length ? "12px" : "0" }, text: "No techniques mapped" }),
          artifacts.length
            ? el("div", {}, [
                el("div", { class: "faint", style: { fontSize: "11px", textTransform: "uppercase", letterSpacing: ".07em", marginBottom: "5px" }, text: "Malware artifacts" }),
                el("div", { class: "grid", style: { gap: "4px" } },
                  artifacts.map((a) => el("div", { class: "mono", style: { fontSize: "12px", color: "var(--bad)", wordBreak: "break-all" }, text: a }))),
              ])
            : null,
        ]);

        // Infrastructure: C2 / network IOCs as chips
        const infraBody = c2.length
          ? el("div", { class: "row wrap", style: { gap: "5px" } },
              c2.map((i) => badge(i, "mono")))
          : empty("No C2 / network IOCs");

        // Victim
        const vicBody = hosts.length
          ? el("div", { class: "grid", style: { gap: "5px" } },
              hosts.map((h) => el("div", { class: "row", style: { gap: "8px" } }, [
                el("span", { style: { width: "6px", height: "6px", borderRadius: "50%", background: "var(--warn)", display: "inline-block", flex: "0 0 auto" } }),
                el("span", { class: "mono", style: { fontSize: "12.5px" }, text: h }),
              ])))
          : empty("No victim hosts identified");

        diamondBody = el("div", { class: "grid cols-2", style: { gap: "14px" } }, [
          vertex("Adversary", "var(--bad)", advBody),
          vertex("Capability", "var(--high)", capBody),
          vertex("Infrastructure", "var(--accent)", infraBody),
          vertex("Victim", "var(--warn)", vicBody),
        ]);
      }

      root.appendChild(card("Diamond Model of Intrusion Analysis", diamondBody,
        { sub: "adversary · capability · infrastructure · victim" }));

      /* ---- court-admissibility note ---- */
      root.appendChild(el("div", {
        class: "muted",
        style: { fontSize: "12.5px", lineHeight: "1.6", marginTop: "16px", padding: "0 2px" },
        html: "<b>Court admissibility.</b> GLASSBOX operates read-only and records every action in a "
          + "hash-chained audit log, establishing an unbroken <b>chain of custody</b>. Before/after SHA-256 "
          + "hashes authenticate each evidence item (<b>FRE 901</b> — authentication) and prove zero spoliation. "
          + "Deterministic replay supplies a documented, reproducible known-error rate (<i>Daubert</i> / FRE 702). "
          + "GLASSBOX does not perform actor attribution.",
      }));
    },
  });
})();
