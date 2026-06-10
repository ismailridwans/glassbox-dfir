/* Timeline — incident narrative + unified cross-source timeline.
 * Contract: GLASSBOX.registerView(id, { title, sub, order, icon, badge?, render }).
 * render(root, ctx): build DOM into `root`. ctx = { state, report, api, ui, go, refresh }.
 *
 * Renders ctx.report.narrative (markdown-ish) as a readable narrative card, then
 * ctx.report.timeline (already sorted) as a vertical timeline with a tactic/source filter.
 */
(function () {
  const ICON = "<svg viewBox='0 0 24 24'><circle cx='12' cy='12' r='9' fill='none' stroke='currentColor' stroke-width='1.6'/><path d='M12 7v5l3.5 2' fill='none' stroke='currentColor' stroke-width='1.6' stroke-linecap='round' stroke-linejoin='round'/></svg>";

  /* dot color per source — keeps the rail readable across evidence types */
  const SRC_KIND = { evtx: "high", registry: "med", memory: "good", pcap: "low", disk: "info" };

  GLASSBOX.registerView("timeline", {
    title: "Timeline",
    sub: "cross-source incident reconstruction",
    order: 40,
    icon: ICON,
    badge: (ctx) => (ctx.report.timeline || []).length || null,
    render(root, ctx) {
      const { ui, report: r } = ctx;
      const { el, card, badge, sevBadge, pill, esc } = ui;

      if (!r || (!r.narrative && !r.timeline)) {
        root.appendChild(ui.empty("Run triage first"));
        return;
      }

      /* ---------- Incident Narrative ---------- */
      if (r.narrative) {
        root.appendChild(card("Incident Narrative", narrativeDom(el, r.narrative),
          { sub: "reconstructed attack chain", class: "", bodyClass: "narrative" }));
      }

      /* ---------- Unified Timeline ---------- */
      const events = Array.isArray(r.timeline) ? r.timeline : [];
      if (!events.length) {
        root.appendChild(el("div", { style: { marginTop: "16px" } },
          card("Unified Timeline", ui.empty("No timeline entries"), { sub: "0 events" })));
        return;
      }

      /* filter options: combine category + source into one select */
      const cats = Array.from(new Set(events.map((e) => e.category).filter(Boolean))).sort();
      const srcs = Array.from(new Set(events.map((e) => e.source).filter(Boolean))).sort();
      const sel = el("select", { class: "input", style: { minWidth: "210px" } }, [
        el("option", { value: "*", text: `All events (${events.length})` }),
        srcs.length ? el("optgroup", { label: "Source" },
          srcs.map((s) => el("option", { value: "src:" + s, text: s }))) : null,
        cats.length ? el("optgroup", { label: "Category" },
          cats.map((c) => el("option", { value: "cat:" + c, text: c.replace(/_/g, " ") }))) : null,
      ]);

      const list = el("div", { class: "trace", style: { marginTop: "4px" } });
      const countLabel = el("span", { class: "sub" });

      const draw = () => {
        const v = sel.value || "*";
        const shown = events.filter((e) => {
          if (v === "*") return true;
          if (v.startsWith("src:")) return e.source === v.slice(4);
          if (v.startsWith("cat:")) return e.category === v.slice(4);
          return true;
        });
        list.innerHTML = "";
        if (!shown.length) { list.appendChild(ui.empty("No events match this filter")); }
        else shown.forEach((e) => list.appendChild(eventRow(el, badge, sevBadge, pill, e)));
        countLabel.textContent = `${shown.length} of ${events.length} events`;
      };
      sel.addEventListener("change", draw);
      draw();

      const toolbar = el("div", { class: "row wrap", style: { gap: "10px", marginBottom: "12px" } }, [
        el("span", { class: "muted", style: { fontSize: "12.5px" }, text: "Filter" }),
        sel, el("span", { class: "spacer", style: { flex: "1" } }), countLabel,
      ]);

      root.appendChild(el("div", { style: { marginTop: "16px" } },
        card("Unified Timeline", el("div", {}, [toolbar, list]),
          { sub: `${events.length} events · ${srcs.length} source(s)` })));
    },
  });

  /* ---- one timeline entry, styled as a .trace-row vertical-line row ---- */
  function eventRow(el, badge, sevBadge, pill, e) {
    const kind = SRC_KIND[e.source] || "info";
    const ts = e.ts && e.ts !== "unknown" ? String(e.ts).replace("T", " ") : "—";
    const techs = (e.technique_ids || []).filter(Boolean);

    return el("div", { class: "trace-row" }, [
      el("div", { class: "t-time", text: ts }),
      el("div", { class: "t-ic", html: dotSvg() }),
      el("div", {}, [
        /* header line: source badge · category · title · severity */
        el("div", { class: "row wrap", style: { gap: "8px" } }, [
          badge((e.source || "?").toUpperCase(), kind),
          e.category ? el("span", { class: "faint", style: { fontSize: "11.5px" },
            text: e.category.replace(/_/g, " ") }) : null,
          el("span", { class: "t-label", style: { fontSize: "13.5px" }, text: e.title || "(untitled)" }),
          el("span", { class: "spacer", style: { flex: "1" } }),
          sevBadge(e.severity),
        ]),
        /* detail */
        e.detail ? el("div", { class: "t-detail", style: { marginTop: "5px", lineHeight: "1.5" }, text: e.detail }) : null,
        /* technique pills + tool_exec_id citation */
        (techs.length || e.tool_exec_id) ? el("div", { class: "row wrap", style: { gap: "6px", marginTop: "7px", alignItems: "center" } }, [
          ...techs.map((t) => pill(t)),
          e.tool_exec_id ? el("span", { class: "mono faint", style: { fontSize: "11px", marginLeft: techs.length ? "4px" : "0" },
            text: "↳ " + e.tool_exec_id }) : null,
        ]) : null,
      ]),
    ]);
  }

  function dotSvg() {
    return "<svg viewBox='0 0 24 24' width='10' height='10'><circle cx='12' cy='12' r='6' fill='currentColor'/></svg>";
  }

  /* ---- minimal markdown-ish → DOM for the narrative string ----
   * handles: '## header', '**bold**', '`code`', '- '/'[+]'/'[~]' bullets,
   * '---' rules, blank lines, and preserves other lines verbatim.
   */
  function narrativeDom(el, text) {
    const wrap = el("div", { class: "narrative-body", style: { fontSize: "13px", lineHeight: "1.6" } });
    String(text).split("\n").forEach((raw) => {
      const line = raw.replace(/\s+$/, "");
      if (line.trim() === "") { wrap.appendChild(el("div", { style: { height: "8px" } })); return; }
      if (/^---+$/.test(line.trim())) { wrap.appendChild(el("hr", { class: "hr" })); return; }

      const h = line.match(/^(#{1,4})\s+(.*)$/);
      if (h) {
        wrap.appendChild(el("div", { style: { fontWeight: "800", fontSize: "13.5px", color: "var(--accent-2)",
          margin: "10px 0 4px", letterSpacing: ".01em" } }, inline(el, h[2])));
        return;
      }

      const bullet = line.match(/^(\s*)(?:-|\[\+\]|\[~\])\s+(.*)$/);
      if (bullet) {
        const isContext = /^\s*\[~\]/.test(line);
        wrap.appendChild(el("div", { class: "row", style: { gap: "8px", alignItems: "baseline",
          paddingLeft: bullet[1].length > 2 ? "14px" : "2px" } }, [
          el("span", { class: "mono", style: { color: isContext ? "var(--faint)" : "var(--good)", flex: "0 0 auto" },
            text: isContext ? "~" : "+" }),
          el("span", {}, inline(el, bullet[2])),
        ]));
        return;
      }

      wrap.appendChild(el("div", {}, inline(el, line)));
    });
    return wrap;
  }

  /* inline: **bold** and `code` → DOM nodes; everything else as text */
  function inline(el, s) {
    const nodes = [];
    const re = /\*\*([^*]+)\*\*|`([^`]+)`/g;
    let last = 0, m;
    while ((m = re.exec(s)) !== null) {
      if (m.index > last) nodes.push(document.createTextNode(s.slice(last, m.index)));
      if (m[1] != null) nodes.push(el("b", { text: m[1] }));
      else nodes.push(el("span", { class: "mono", style: { color: "var(--accent)", fontSize: "11.5px" }, text: m[2] }));
      last = re.lastIndex;
    }
    if (last < s.length) nodes.push(document.createTextNode(s.slice(last)));
    return nodes.length ? nodes : [document.createTextNode(s)];
  }
})();
