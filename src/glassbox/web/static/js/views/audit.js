/* Audit Trail — hash-chained, tamper-evident chain of custody.
 * Contract: GLASSBOX.registerView(id, { title, sub, order, icon, badge?, render }).
 * render(root, ctx) is async: fetches ctx.api.audit() and builds DOM into `root`.
 * Each record's hash covers the previous record's hash → any tamper breaks the chain.
 */
(function () {
  const ICON = "<svg viewBox='0 0 24 24'><path d='M8.5 12a3.5 3.5 0 0 1 3.5-3.5h2a3.5 3.5 0 0 1 0 7' fill='none' stroke='currentColor' stroke-width='1.6' stroke-linecap='round'/><path d='M15.5 12a3.5 3.5 0 0 1-3.5 3.5h-2a3.5 3.5 0 0 1 0-7' fill='none' stroke='currentColor' stroke-width='1.6' stroke-linecap='round'/></svg>";

  const CAP = 300; // max rendered chain rows

  /* compact one-line summary of the most relevant fields per event type */
  function summarize(ev) {
    if (!ev || typeof ev !== "object") return "";
    const t = ev.type;
    const j = (a) => (Array.isArray(a) ? a : []).join(", ");
    switch (t) {
      case "case_open":
        return `${ev.case_id || "?"} · ${(ev.glassbox_tools || []).length} tools · max_iter ${ev.max_iterations}${ev.replay ? " · replay" : ""}`;
      case "integrity_baseline":
        return `baseline ${(ev.files || []).length} file(s) hashed`;
      case "integrity_verify":
        return `${(ev.results || []).length} file(s) re-hashed · ${ev.spoliation_detected ? "SPOLIATION" : "intact"}`;
      case "plan":
        return `iteration ${ev.iteration} · ${(ev.steps || []).length} step(s) planned`;
      case "tool_execution":
        return `${ev.tool} (${ev.agent || "?"}) · ${ev.status} · ${ev.n_records != null ? ev.n_records + " rec" : "—"} · ${ev.duration_ms != null ? ev.duration_ms + "ms" : ""}`;
      case "specialist_result":
        return `${ev.agent} · ${ev.n_findings} finding(s) · ${(ev.tools || []).length} tool(s)`;
      case "detection_modules":
        return `credential ${ev.credential} · lateral ${ev.lateral}`;
      case "correlation":
        return `${ev.n_discrepancies} discrepancy(ies)${(ev.kinds || []).length ? " · " + j(ev.kinds) : ""}`;
      case "attack_mapping":
        return `${(ev.techniques || []).length} technique(s) · ${ev.finding_ioc_count} IOC(s)`;
      case "verification":
        return `${ev.finding_id} · ${ev.verdict} · score ${ev.confidence_score}${ev.epistemic_type ? " · " + ev.epistemic_type : ""}`;
      case "adversarial_review":
        return `${ev.finding_id} · ${ev.verdict} · uphold ${ev.uphold_weight} / refute ${ev.refute_weight}`;
      case "discrepancy_verification":
        return `${ev.discrepancy_id} · ${ev.verdict}${(ev.reasons || []).length ? " · " + j(ev.reasons) : ""}`;
      case "critique":
        return `iteration ${ev.iteration} · ${ev.done ? "done" : "continue"} · ${(ev.gaps || []).length} gap(s)`;
      case "investigation_depth":
        return `${ev.novel} novel / ${ev.parroted} parroted · score ${ev.investigation_depth_score}`;
      case "lessons_learned":
        return `${ev.new_lessons} new lesson(s)`;
      case "approval_gate":
        return `${ev.pending} pending · ${ev.approved} approved · ${ev.rejected} rejected`;
      case "report":
        return `${ev.n_findings} findings · ${ev.red_team_verified} red-team ✓ · ${ev.n_quarantined} quarantined · chain ${ev.audit_chain_valid ? "valid" : "BROKEN"}`;
      default: {
        // generic fallback: pick a few primitive fields
        const parts = [];
        for (const [k, v] of Object.entries(ev)) {
          if (k === "type") continue;
          if (v == null || typeof v === "object") continue;
          parts.push(`${k} ${v}`);
          if (parts.length >= 3) break;
        }
        return parts.join(" · ");
      }
    }
  }

  /* badge kind for an event-type's verdict-ish state, when one applies */
  function verdictBadge(ui, ev) {
    const v = ev.verdict;
    if (ev.type === "adversarial_review") {
      if (v === "UPHELD") return ui.badge("UPHELD", "good");
      if (v === "REFUTED") return ui.badge("REFUTED", "bad");
      if (v === "DEMOTED") return ui.badge("DEMOTED", "warn");
    }
    if (ev.type === "tool_execution" && ev.status && ev.status !== "OK") return ui.badge(ev.status, "warn");
    if (ev.type === "integrity_verify") return ui.badge(ev.spoliation_detected ? "SPOLIATION" : "INTACT", ev.spoliation_detected ? "bad" : "good");
    if (ev.type === "report") return ui.badge(ev.audit_chain_valid ? "VALID" : "BROKEN", ev.audit_chain_valid ? "good" : "bad");
    return null;
  }

  GLASSBOX.registerView("audit", {
    title: "Audit Trail", sub: "tamper-evident chain of custody", order: 80, icon: ICON,
    async render(root, ctx) {
      const { ui } = ctx;
      const { el, card, stat, badge } = ui;

      // No run yet → guard. (audit() can still 404/empty before triage.)
      if (!ctx.report || !ctx.report.findings) {
        root.appendChild(ui.empty("Run triage first"));
        return;
      }

      let data;
      try {
        data = await ctx.api.audit();
      } catch (e) {
        root.appendChild(ui.empty("Audit log unavailable: " + (e.message || e)));
        return;
      }
      if (!data || !Array.isArray(data.records) || !data.records.length) {
        root.appendChild(ui.empty("No audit records yet"));
        return;
      }

      // Mutable filter state, re-rendered into `chainHost` without a full reload.
      let typeFilter = "all";

      /* ---- live region for re-verify status ---- */
      const reverifyNote = el("span", { class: "faint", style: { fontSize: "12px" } });

      /* ---- top banner card: big status + counts + explanation ---- */
      const bannerHost = el("div", { style: { marginBottom: "16px" } });

      function buildBanner(d) {
        const valid = d.valid === true;
        const errs = d.errors || [];
        const big = el("div", {
          class: "stat-value",
          style: { fontSize: "30px", lineHeight: "1.1", color: valid ? "var(--good)" : "var(--bad)" },
          text: valid ? "CHAIN VALID" : "CHAIN BROKEN",
        });
        const body = el("div", { class: "row", style: { gap: "20px", alignItems: "center", flexWrap: "wrap" } }, [
          el("div", {}, [
            big,
            el("div", { class: "muted", style: { fontSize: "12.5px", marginTop: "4px" },
              html: `${ui.fmtNum(d.count != null ? d.count : d.records.length)} records${errs.length ? " · <span style='color:var(--bad)'>" + errs.length + " error(s)</span>" : ""}` }),
          ]),
          el("div", { class: "muted", style: { fontSize: "12.5px", maxWidth: "520px", lineHeight: "1.5" },
            html: "Every record's hash covers the <b>previous</b> record's hash, forming an append-only chain. Recomputing the chain detects any insertion, deletion, or edit — so the log is <b>tamper-evident</b> (verifiable chain of custody)." }),
        ]);
        const errList = errs.length
          ? el("div", { class: "mono", style: { marginTop: "10px", fontSize: "11.5px", color: "var(--bad)" },
              html: errs.slice(0, 5).map(ui.esc).join("<br>") })
          : null;
        const action = el("div", { class: "row", style: { gap: "10px", alignItems: "center" } }, [
          reverifyNote,
          el("button", { class: "btn btn-sm btn-primary", text: "Re-verify chain", onclick: reverify }),
        ]);
        return card("Chain of Custody", el("div", {}, [body, errList]),
          { sub: "hash-chained audit log", action });
      }

      async function reverify(ev) {
        const btn = ev && ev.currentTarget;
        if (btn) { btn.disabled = true; btn.textContent = "Verifying…"; }
        reverifyNote.textContent = "";
        try {
          const fresh = await ctx.api.audit();
          data = fresh;
          bannerHost.innerHTML = "";
          bannerHost.appendChild(buildBanner(data));
          buildChain(); // rebuild rows + keep/repopulate filter
          reverifyNote.textContent = (data.valid ? "✓ verified " : "✗ broken ") + new Date().toLocaleTimeString();
          reverifyNote.style.color = data.valid ? "var(--good)" : "var(--bad)";
        } catch (e) {
          reverifyNote.textContent = "re-verify failed";
          reverifyNote.style.color = "var(--bad)";
        }
      }

      /* ---- event-type filter select ---- */
      const types = Array.from(new Set(data.records.map((r) => (r.event && r.event.type) || "?"))).sort();
      const select = el("select", { class: "input", style: { minWidth: "200px" },
        onchange: (e) => { typeFilter = e.target.value; buildChain(); } },
        [el("option", { value: "all", text: `All event types (${data.records.length})` })].concat(
          types.map((t) => {
            const n = data.records.filter((r) => ((r.event && r.event.type) || "?") === t).length;
            return el("option", { value: t, text: `${t} (${n})` });
          })));

      const countNote = el("span", { class: "faint", style: { fontSize: "12px" } });
      const toolbar = el("div", { class: "toolbar", style: { marginBottom: "12px", gap: "12px", alignItems: "center" } }, [
        el("span", { class: "muted", style: { fontSize: "12.5px" }, text: "Filter event type:" }),
        select,
        countNote,
      ]);

      /* ---- chain host (records) ---- */
      const chainHost = el("div");

      function buildChain() {
        const recs = data.records
          .filter((r) => typeFilter === "all" || ((r.event && r.event.type) || "?") === typeFilter)
          .slice()
          .sort((a, b) => (a.seq || 0) - (b.seq || 0));

        const total = recs.length;
        const shown = recs.slice(0, CAP);
        countNote.textContent = `showing ${shown.length} of ${total}`;

        const chain = el("div", { class: "chain" });
        shown.forEach((r, i) => {
          const ev = r.event || {};
          const hash = String(r.record_hash || "");
          const rec = el("div", { class: "chain-rec", title: `seq ${r.seq} · ${r.ts || ""}\nrecord_hash ${hash}\nprev_hash ${r.prev_hash || ""}` }, [
            el("span", { class: "seq", text: "#" + (r.seq != null ? r.seq : "?") }),
            el("span", { class: "etype", text: ev.type || "?" }),
            el("div", { class: "row", style: { gap: "8px", alignItems: "center", minWidth: "0" } }, [
              el("span", { class: "muted", style: { fontSize: "12px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }, text: summarize(ev) }),
              verdictBadge(ui, ev),
            ]),
            el("span", { class: "hash", title: hash, text: hash ? hash.slice(0, 12) : "—" }),
          ]);
          chain.appendChild(rec);
          // tiny visual link between consecutive records
          if (i < shown.length - 1) chain.appendChild(el("div", { class: "chain-link" }));
        });

        chainHost.innerHTML = "";
        chainHost.appendChild(chain);
        if (total > CAP) {
          chainHost.appendChild(el("div", { class: "muted", style: { marginTop: "10px", fontSize: "12px" },
            text: `… ${ui.fmtNum(total - CAP)} more record(s) not rendered (capped at ${CAP}).` }));
        }
      }

      /* ---- top stat tiles ---- */
      const typeCounts = {};
      data.records.forEach((r) => { const t = (r.event && r.event.type) || "?"; typeCounts[t] = (typeCounts[t] || 0) + 1; });
      const topType = Object.entries(typeCounts).sort((a, b) => b[1] - a[1])[0] || ["—", 0];
      root.appendChild(el("div", { class: "grid cols-4", style: { marginBottom: "16px" } }, [
        stat("Chain Status", data.valid ? "VALID" : "BROKEN", { tone: data.valid ? "good" : "bad",
          foot: data.valid ? "tamper-evident" : `${(data.errors || []).length} integrity error(s)` }),
        stat("Records", ui.fmtNum(data.count != null ? data.count : data.records.length), { tone: "accent", foot: "append-only entries" }),
        stat("Event Types", types.length, { foot: "distinct kinds logged" }),
        stat("Most Frequent", topType[1], { foot: ui.esc(String(topType[0])) }),
      ]));

      /* ---- assemble ---- */
      bannerHost.appendChild(buildBanner(data));
      root.appendChild(bannerHost);

      const chainCard = card("Audit Records", el("div", {}, [toolbar, chainHost]),
        { sub: "each row links to the previous via its hash" });
      root.appendChild(chainCard);

      buildChain();
    },
  });
})();
