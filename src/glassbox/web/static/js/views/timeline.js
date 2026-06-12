/* Timeline v2 — phased incident narrative (collapsible) + connected cross-source event rail.
 * Contract: GLASSBOX.registerView(id, { title, sub, order, icon, badge?, render }).
 * Consumes ctx.report.narrative (markdown-ish phased string) and ctx.report.timeline[]
 * (events: { ts, source, category, title, severity, confidence, tool_exec_id, technique_ids[], detail }).
 */
(function () {
  const ICON = "<svg viewBox='0 0 24 24'><circle cx='12' cy='12' r='9' fill='none' stroke='currentColor' stroke-width='1.6'/><path d='M12 7v5l3.5 2' fill='none' stroke='currentColor' stroke-width='1.6' stroke-linecap='round' stroke-linejoin='round'/></svg>";

  const SRC = {
    evtx:     { kind: "high", label: "EVTX" },
    registry: { kind: "med",  label: "REGISTRY" },
    memory:   { kind: "good", label: "MEMORY" },
    pcap:     { kind: "low",  label: "PCAP" },
    disk:     { kind: "info", label: "DISK" },
  };
  const KIND_VAR = { high: "--high", med: "--med", good: "--up", low: "--low", info: "--info" };

  GLASSBOX.registerView("timeline", {
    title: "Timeline",
    sub: "cross-source incident reconstruction",
    order: 40,
    icon: ICON,
    badge: (ctx) => (ctx.report.timeline || []).length || null,
    render(root, ctx) {
      const { ui, report: r } = ctx;
      const { el, card, badge, sevBadge, pill, cssVar } = ui;
      const srcColor = (s) => cssVar(KIND_VAR[(SRC[s] && SRC[s].kind) || "info"]);

      if (!r || (!r.narrative && !r.timeline)) { root.appendChild(ui.empty("Run triage first")); return; }

      /* ---------- 1. Incident Narrative (phased, collapsible) ---------- */
      if (r.narrative) {
        const n = parseNarrative(r.narrative);
        const phasesWrap = el("div", { class: "rise" });
        n.phases.forEach((p, i) => phasesWrap.appendChild(phaseCard(el, badge, pill, p, i)));
        const lead = n.lead ? el("div", { class: "muted", style: { fontSize: "13px", margin: "0 0 14px", lineHeight: "1.6" }, text: n.lead }) : null;
        const summ = n.summary ? el("div", { class: "row wrap", style: { gap: "8px", marginTop: "12px", paddingTop: "12px", borderTop: "1px solid var(--border)", fontSize: "12.5px", color: "var(--muted)" } }, inlineNodes(el, n.summary)) : null;
        root.appendChild(card("Incident Narrative",
          el("div", {}, [lead, phasesWrap, summ].filter(Boolean)),
          { sub: "reconstructed attack chain", action: badge(`${n.phases.length} phases`, "ghost") }));
      }

      /* ---------- 2. Unified cross-source event rail ---------- */
      const events = Array.isArray(r.timeline) ? r.timeline.slice() : [];
      if (!events.length) {
        root.appendChild(el("div", { style: { marginTop: "16px" } },
          card("Unified Timeline", ui.empty("No timeline entries"), { sub: "0 events" })));
        return;
      }

      const presentSrcs = Array.from(new Set(events.map((e) => e.source).filter(Boolean)));
      const active = new Set(presentSrcs);      // all on by default
      let query = "";

      // sticky filter bar: source chips + search
      const chips = presentSrcs.map((s) => {
        const c = el("button", { class: "src-chip on", "data-src": s }, [
          el("span", { class: "sd", style: { background: srcColor(s) } }),
          (SRC[s] && SRC[s].label) || s.toUpperCase(),
        ]);
        c.addEventListener("click", () => {
          if (active.has(s)) { active.delete(s); c.classList.remove("on"); c.classList.add("off"); }
          else { active.add(s); c.classList.add("on"); c.classList.remove("off"); }
          draw();
        });
        return c;
      });
      const search = el("input", { class: "input", placeholder: "Search events, techniques, tools…", style: { minWidth: "230px", flex: "1" },
        oninput: (e) => { query = e.target.value.toLowerCase().trim(); draw(); } });
      const countLabel = el("span", { class: "faint", style: { fontSize: "12px", whiteSpace: "nowrap" } });
      const bar = el("div", { class: "sticky-bar" }, [
        el("span", { class: "muted", style: { fontSize: "12px", fontWeight: "600" }, text: "Sources" }),
        ...chips,
        el("span", { class: "spacer", style: { flex: ".4" } }),
        search, countLabel,
      ]);

      const railHost = el("div", { class: "tl" });
      const draw = () => {
        const shown = events.filter((e) => {
          if (e.source && !active.has(e.source)) return false;
          if (!query) return true;
          const hay = `${e.title} ${e.detail || ""} ${(e.technique_ids || []).join(" ")} ${e.tool_exec_id || ""} ${e.category || ""}`.toLowerCase();
          return hay.includes(query);
        });
        countLabel.textContent = `${shown.length} of ${events.length} events`;
        railHost.innerHTML = "";
        if (!shown.length) { railHost.appendChild(ui.empty("No events match these filters")); return; }
        let lastHour = null;
        shown.forEach((e, idx) => {
          const hour = hourOf(e.ts);
          if (hour !== lastHour) {
            railHost.appendChild(el("div", { class: "tl-hour" }, [
              el("span", { class: "hh", text: hour }), el("span", { class: "hl" }),
            ]));
            lastHour = hour;
          }
          railHost.appendChild(eventItem(el, badge, sevBadge, pill, e, srcColor, idx === shown.length - 1));
        });
      };
      draw();

      root.appendChild(el("div", { style: { marginTop: "16px" } },
        card("Unified Timeline", el("div", {}, [bar, railHost]),
          { sub: `${events.length} events · ${presentSrcs.length} source(s)` })));
    },
  });

  /* ---------- event rail item ---------- */
  function eventItem(el, badge, sevBadge, pill, e, srcColor, isLast) {
    const src = e.source || "?";
    const meta = SRC[src] || { kind: "info", label: src.toUpperCase() };
    const techs = (e.technique_ids || []).filter(Boolean);
    const time = timeOf(e.ts);
    const item = el("div", { class: "tl-item" + (isLast ? " is-last" : "") }, [
      el("div", { class: "tl-time", text: time }),
      el("div", { class: "tl-rail" }, el("div", { class: "tl-node", style: { "--node": srcColor(src) } })),
      el("div", { class: "tl-content" },
        el("div", { class: "tl-card" }, [
          el("div", { class: "row wrap", style: { gap: "8px", alignItems: "center" } }, [
            badge(meta.label, meta.kind),
            e.category ? el("span", { class: "faint", style: { fontSize: "11px" }, text: e.category.replace(/_/g, " ") }) : null,
            el("span", { class: "tl-title", text: e.title || "(untitled)" }),
            el("span", { class: "spacer", style: { flex: "1" } }),
            sevBadge(e.severity),
          ]),
          e.detail ? el("div", { class: "tl-detail", text: e.detail }) : null,
          (techs.length || e.tool_exec_id) ? el("div", { class: "tl-foot" }, [
            ...techs.map((t) => pill(t)),
            e.tool_exec_id ? el("span", { class: "tl-tool", text: "↳ " + e.tool_exec_id }) : null,
          ]) : null,
        ])),
    ]);
    return item;
  }

  function hourOf(ts) {
    if (!ts || ts === "unknown") return "Unknown time";
    const t = String(ts).split("T")[1] || "";
    const hh = t.slice(0, 2);
    return hh ? hh + ":00" : "Unknown time";
  }
  function timeOf(ts) {
    if (!ts || ts === "unknown") return "—";
    const t = String(ts).split("T")[1] || String(ts);
    return t.slice(0, 8) || "—";
  }

  /* ---------- narrative parsing → phases ---------- */
  function parseNarrative(text) {
    const out = { caseTitle: "", lead: "", phases: [], summary: "" };
    let cur = null;
    String(text).split("\n").forEach((raw) => {
      const line = raw.replace(/\s+$/, "");
      if (!line.trim()) return;
      let m;
      if ((m = line.match(/^##\s+(.*)$/))) { out.caseTitle = m[1]; return; }
      if (/^\*\*Summary:\*\*/.test(line)) { out.summary = line.replace(/^\*\*Summary:\*\*\s*/, "**Summary:** "); return; }
      if ((m = line.match(/^\*\*(Phase\s+\d+:[^*]+)\*\*\s*(?:\(([^)]+)\))?/))) {
        cur = { title: m[1].trim(), time: (m[2] || "").trim(), events: [], more: 0 };
        out.phases.push(cur); return;
      }
      if ((m = line.match(/^\s*\[([+~])\]\s+(.*)$/))) {
        if (!cur) { cur = { title: "Phase: Observations", time: "", events: [], more: 0 }; out.phases.push(cur); }
        cur.events.push(parseBullet(m[1], m[2])); return;
      }
      if ((m = line.match(/^\s*\.\.\.\s+and\s+(\d+)\s+more/))) { if (cur) cur.more = parseInt(m[1], 10); return; }
      if (!cur && /reconstructed|attack chain/i.test(line)) { out.lead = line; return; }
    });
    return out;
  }
  function parseBullet(kind, text) {
    let tool = null, t = text;
    const tm = t.match(/`\[([^\]]+)\]`\s*/);
    if (tm) { tool = tm[1]; t = t.replace(tm[0], ""); }
    const techs = [];
    const techMatch = t.match(/\[((?:T\d{4}(?:\.\d{3})?(?:,\s*)?)+)\]\s*$/);
    if (techMatch) { techMatch[1].split(/,\s*/).forEach((x) => techs.push(x.trim())); t = t.replace(techMatch[0], "").trim(); }
    return { kind, tool, techs, text: t.replace(/\s+$/, "") };
  }

  /* ---------- phase card (collapsible) ---------- */
  function phaseCard(el, badge, pill, p, i) {
    const num = (p.title.match(/Phase\s+(\d+)/) || [])[1] || (i + 1);
    const name = p.title.replace(/^Phase\s+\d+:\s*/, "");
    const body = el("div", { class: "phase-body" });
    p.events.forEach((ev) => {
      const dotColor = ev.kind === "+" ? "var(--up)" : "var(--faint)";
      body.appendChild(el("div", { class: "pevent" + (ev.kind === "~" ? " context" : "") }, [
        el("span", { class: "pe-dot", style: { background: dotColor } }),
        el("span", { class: "pe-text" }, [
          ...inlineNodes(el, ev.text),
          ev.tool ? el("span", { class: "mono", style: { fontSize: "10.5px", color: "var(--faint)", marginLeft: "6px" }, text: "↳ " + ev.tool }) : null,
        ].filter(Boolean)),
        ev.techs.length ? el("span", { class: "row wrap", style: { gap: "4px", justifyContent: "flex-end" } }, ev.techs.map((t) => el("span", { class: "pe-tid", text: t }))) : el("span"),
      ]));
    });
    if (p.more) body.appendChild(el("div", { class: "pevent context" }, [
      el("span"), el("span", { class: "pe-text faint", style: { fontSize: "11.5px" }, text: `… and ${p.more} more observation(s)` }), el("span"),
    ]));

    const phase = el("div", { class: "phase" + (i > 1 ? " collapsed" : "") }, [
      el("div", { class: "phase-head" }, [
        el("div", { class: "pidx", text: String(num) }),
        el("div", { class: "pt" }, [
          el("div", { class: "ptitle", text: name }),
          p.time ? el("div", { class: "ptime", text: p.time.replace(/T/g, " ") }) : null,
        ]),
        el("div", { class: "pright" }, [
          badge(`${p.events.length + (p.more || 0)} event${p.events.length + (p.more || 0) === 1 ? "" : "s"}`, "ghost"),
          el("span", { class: "chev", html: "<svg viewBox='0 0 24 24' width='16' height='16'><path d='M6 9l6 6 6-6' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'/></svg>" }),
        ]),
      ]),
      body,
    ]);
    phase.querySelector(".phase-head").addEventListener("click", () => phase.classList.toggle("collapsed"));
    return phase;
  }

  /* inline: **bold** and `code` → DOM nodes */
  function inlineNodes(el, s) {
    const nodes = [];
    const re = /\*\*([^*]+)\*\*|`([^`]+)`/g;
    let last = 0, m;
    while ((m = re.exec(s)) !== null) {
      if (m.index > last) nodes.push(document.createTextNode(s.slice(last, m.index)));
      if (m[1] != null) nodes.push(el("b", { text: m[1] }));
      else nodes.push(el("span", { class: "mono", style: { color: "var(--brand-2)", fontSize: "11px" }, text: m[2] }));
      last = re.lastIndex;
    }
    if (last < s.length) nodes.push(document.createTextNode(s.slice(last)));
    return nodes.length ? nodes : [document.createTextNode(s)];
  }
})();
