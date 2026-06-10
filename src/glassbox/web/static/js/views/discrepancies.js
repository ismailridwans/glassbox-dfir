/* Cross-Source Discrepancies — where one evidence source contradicts another.
 * Contract: GLASSBOX.registerView(id, { title, sub, order, icon, badge?, render }).
 * render(root, ctx): build DOM into `root`. ctx = { state, report, api, ui, go, refresh }.
 */
(function () {
  // Split/diverging arrows — two sources telling two stories.
  const ICON = "<svg viewBox='0 0 24 24'><path d='M4 7h6l3 5h7' fill='none' stroke='currentColor' stroke-width='1.6' stroke-linecap='round' stroke-linejoin='round'/><path d='M4 17h6l3-5' fill='none' stroke='currentColor' stroke-width='1.6' stroke-linecap='round' stroke-linejoin='round'/><path d='M17 9l3 3-3 3' fill='none' stroke='currentColor' stroke-width='1.6' stroke-linecap='round' stroke-linejoin='round'/></svg>";

  // Human-friendly labels for the kinds we know about (falls back to the raw key, prettified).
  const KIND_LABELS = {
    hidden_process: "Hidden Process",
    orphan_connection: "Orphan Connection",
    disk_memory_mismatch: "Disk ⇄ Memory Mismatch",
    timeline_conflict: "Timeline Conflict",
    unlinked_dll: "Unlinked DLL",
  };
  const prettyKind = (k) =>
    KIND_LABELS[k] || String(k || "unknown").replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());

  // CONFIRMED → good, INFERRED → warn, HALLUCINATED → bad, else ghost.
  const confKind = (c) =>
    ({ CONFIRMED: "good", INFERRED: "warn", HALLUCINATED: "bad" }[String(c || "").toUpperCase()] || "ghost");

  GLASSBOX.registerView("discrepancies", {
    title: "Discrepancies",
    sub: "cross-source correlation conflicts",
    order: 70,
    icon: ICON,
    badge: (ctx) => (ctx.report.discrepancies || []).length,
    render(root, ctx) {
      const { ui, report: r } = ctx;
      const { el, card, stat, badge, sevBadge, pill, empty, sevKey } = ui;

      // Always guard missing data — never throw.
      if (!r || !r.discrepancies) {
        root.appendChild(empty("Run triage first"));
        return;
      }

      const discs = r.discrepancies || [];

      /* ---- intro card: what cross-source correlation means ---- */
      root.appendChild(card("Cross-Source Correlation",
        el("div", { class: "muted", style: { fontSize: "13px", lineHeight: "1.6" } }, [
          el("div", {}, "A single tool can be fooled; two independent sources rarely lie the same way. " +
            "GLASSBOX cross-checks every artifact against the others and flags the seams where they disagree — " +
            "these contradictions are often the clearest fingerprint of an active adversary."),
          el("div", { class: "row wrap", style: { gap: "8px", marginTop: "10px" } }, [
            pill("rootkit hides a process from pslist, but psscan still sees it"),
            pill("a network connection outlives the process that opened it"),
            pill("a file on disk has no matching trace in memory"),
          ]),
        ]),
        { sub: "why discrepancies matter" }));

      /* ---- empty state: reassuring when nothing diverges ---- */
      if (!discs.length) {
        root.appendChild(el("div", { style: { marginTop: "16px" } },
          empty("No cross-source discrepancies. Every source agrees — disk, memory, and network tell one consistent story.",
            "<svg viewBox='0 0 24 24' width='40' height='40'><circle cx='12' cy='12' r='9' fill='none' stroke='currentColor' stroke-width='1.4'/><path d='M8 12.5l2.5 2.5L16 9' fill='none' stroke='currentColor' stroke-width='1.6' stroke-linecap='round' stroke-linejoin='round'/></svg>")));
        return;
      }

      /* ---- stat tiles: total + count by kind ---- */
      const kindCounts = {};
      discs.forEach((d) => { const k = d.kind || "unknown"; kindCounts[k] = (kindCounts[k] || 0) + 1; });
      const kindEntries = Object.entries(kindCounts).sort((a, b) => b[1] - a[1]);

      const tiles = [
        stat("Discrepancies", discs.length, { tone: "accent", foot: `${kindEntries.length} distinct kind(s)` }),
      ];
      kindEntries.slice(0, 3).forEach(([k, n]) => {
        tiles.push(stat(prettyKind(k), n, { tone: "warn", foot: "cross-source conflict" }));
      });
      // Pad to a clean 4-wide row when fewer than 3 kinds.
      const cols = Math.min(4, tiles.length);
      root.appendChild(el("div", { class: "grid cols-" + cols, style: { marginBottom: "16px" } }, tiles));

      /* ---- one card per discrepancy ---- */
      const ordered = [...discs].sort((a, b) =>
        ui.SEV.indexOf(String(a.severity || "INFO").toUpperCase()) -
        ui.SEV.indexOf(String(b.severity || "INFO").toUpperCase()));

      const list = el("div", { class: "grid", style: { gap: "12px" } }, ordered.map((d) => {
        const k = sevKey(d.severity);

        // Header row: kind badge + severity + confidence, with id on the right.
        const head = el("div", { class: "row", style: { justifyContent: "space-between", alignItems: "center", gap: "10px" } }, [
          el("div", { class: "row wrap", style: { gap: "7px", alignItems: "center" } }, [
            badge(prettyKind(d.kind), "ghost"),
            sevBadge(d.severity),
            d.confidence ? badge(String(d.confidence).toUpperCase(), confKind(d.confidence)) : null,
          ]),
          d.discrepancy_id ? el("span", { class: "mono faint", style: { fontSize: "11.5px" }, text: d.discrepancy_id }) : null,
        ]);

        // Source badges (e.g. memory / disk / pcap).
        const sources = (d.sources || []).length
          ? el("div", { class: "row wrap", style: { gap: "6px", marginTop: "9px" } },
              (d.sources || []).map((s) => badge(String(s).toUpperCase(), "info")))
          : null;

        // Description.
        const desc = el("div", { class: "f-desc", style: { marginTop: "9px", fontSize: "13px", lineHeight: "1.55" },
          text: d.description || "(no description)" });

        // Provenance: tool_exec_id ⇐ raw_locator (+ note when present).
        const provRows = (d.provenance || []).map((p) => {
          const left = p.tool_exec_id || p.tool || "—";
          const right = p.raw_locator != null && p.raw_locator !== "" ? String(p.raw_locator) : "—";
          const txt = `${left} ⇐ ${right}` + (p.note ? `  ·  ${p.note}` : "");
          return el("div", { class: "f-prov", text: txt });
        });
        const prov = provRows.length
          ? el("div", { style: { marginTop: "10px" } }, provRows)
          : null;

        return el("div", { class: "card sev-rail " + k, style: { padding: "13px 15px" } },
          [head, sources, desc, prov].filter(Boolean));
      }));

      root.appendChild(card("Detected Discrepancies", list,
        { sub: `${discs.length} cross-source conflict(s), worst-first` }));
    },
  });
})();
