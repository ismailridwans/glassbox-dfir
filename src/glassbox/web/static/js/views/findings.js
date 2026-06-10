/* Findings Explorer — filterable, sortable, evidence-grounded finding cards.
 * Contract: GLASSBOX.registerView(id, { title, sub, order, icon, badge?, render }).
 * render(root, ctx): build DOM into `root`. ctx = { state, report, api, ui, go, refresh }.
 */
(function () {
  // magnifying glass over a document — "explore the findings"
  const ICON = "<svg viewBox='0 0 24 24'><path d='M6 3h8l4 4v6' fill='none' stroke='currentColor' stroke-width='1.6' stroke-linejoin='round'/><path d='M14 3v4h4' fill='none' stroke='currentColor' stroke-width='1.6' stroke-linejoin='round'/><circle cx='9' cy='15' r='3.2' fill='none' stroke='currentColor' stroke-width='1.6'/><path d='M11.4 17.4L14 20' fill='none' stroke='currentColor' stroke-width='1.6' stroke-linecap='round'/></svg>";

  GLASSBOX.registerView("findings", {
    title: "Findings",
    sub: "grounded + red-team verified",
    order: 30,
    icon: ICON,
    badge: (ctx) => ((ctx.report || {}).findings || []).length || null,

    render(root, ctx) {
      const { ui, report: r } = ctx;
      const { el, card, badge, sevBadge, pill, empty, esc, sevKey, SEV } = ui;

      if (!r || !r.findings) { root.appendChild(empty("Run triage first")); return; }

      const findings = r.findings || [];
      if (!findings.length) { root.appendChild(empty("No findings in this report")); return; }

      /* ---- filter state ---- */
      const filters = { sev: "ALL", verdict: "ALL", q: "" };

      /* ---- toolbar (built once, never rebuilt on filter change) ---- */
      const sevSel = el("select", { class: "input" },
        ["ALL", ...SEV].map((s) => el("option", { value: s, text: s === "ALL" ? "All severities" : s })));
      const verdictSel = el("select", { class: "input" }, [
        el("option", { value: "ALL", text: "All verdicts" }),
        el("option", { value: "UPHELD", text: "Red-team verified" }),
        el("option", { value: "DEMOTED", text: "Demoted" }),
      ]);
      const search = el("input", { class: "input", type: "search", placeholder: "Search title, description, IOC, technique…", style: { minWidth: "240px" } });
      const count = el("span", { class: "muted", style: { fontSize: "12.5px", whiteSpace: "nowrap" } });

      const toolbar = el("div", { class: "toolbar" }, [
        sevSel, verdictSel, search, el("span", { class: "spacer" }), count,
      ]);
      root.appendChild(toolbar);

      /* ---- list container (the only thing re-rendered) ---- */
      const list = el("div", { class: "grid", style: { gap: "10px" } });
      root.appendChild(list);

      /* ---- helpers ---- */
      function matches(f) {
        const sev = String(f.severity || "INFO").toUpperCase();
        if (filters.sev !== "ALL" && sev !== filters.sev) return false;
        if (filters.verdict !== "ALL" && f.adversarial_verdict !== filters.verdict) return false;
        if (filters.q) {
          const hay = [
            f.title, f.description, f.epistemic_type, f.host, f.source_agent,
            ...(f.cited_values || []),
            ...(f.attack || []).map((m) => `${m.technique_id} ${m.technique_name}`),
            ...(f.iocs || []).map((i) => `${i.value} ${i.defanged}`),
          ].join(" ").toLowerCase();
          if (!hay.includes(filters.q)) return false;
        }
        return true;
      }

      function fcard(f) {
        const k = sevKey(f.severity);
        const meta = el("div", { class: "f-meta" });

        meta.appendChild(sevBadge(f.severity));
        if (f.confidence) meta.appendChild(badge(f.confidence, f.confidence === "CONFIRMED" ? "good" : "ghost"));
        if (f.epistemic_type) meta.appendChild(pill(f.epistemic_type));
        if (f.adversarial_verdict === "UPHELD") meta.appendChild(badge("RED-TEAM VERIFIED", "good"));
        else if (f.adversarial_verdict === "DEMOTED") meta.appendChild(badge("demoted", "ghost"));
        if (f.confidence_score != null)
          meta.appendChild(el("span", { class: "mono faint", style: { fontSize: "11.5px" }, text: "score " + Number(f.confidence_score).toFixed(2) }));
        if (f.requires_human_review) meta.appendChild(badge("⚠ needs human review", "warn"));

        const kids = [
          el("div", { class: "f-title", text: f.title || f.finding_id || "(untitled finding)" }),
          meta,
        ];

        if (f.description) kids.push(el("div", { class: "f-desc", text: f.description }));

        // ATT&CK technique pills
        const attack = (f.attack || []).filter((m) => m && m.technique_id);
        if (attack.length)
          kids.push(el("div", { class: "row wrap", style: { gap: "6px", marginTop: "8px" } },
            attack.map((m) => el("span", { class: "pill", title: m.technique_name || "", text: m.technique_id }))));

        // IOC chips
        const iocs = (f.iocs || []).filter((i) => i && (i.defanged || i.value));
        if (iocs.length)
          kids.push(el("div", { class: "row wrap", style: { gap: "6px", marginTop: "8px" } },
            iocs.map((i) => el("span", {
              class: "badge mono",
              title: i.context || i.type || "",
              text: (i.type ? i.type + " " : "") + (i.defanged || i.value),
            }))));

        // expandable provenance + red-team votes
        const prov = (f.provenance || []).filter(Boolean);
        const votes = (f.skeptic_votes || []).filter(Boolean);
        if (prov.length || votes.length) {
          const det = el("details");
          det.appendChild(el("summary", { text: "Provenance & red-team" }));
          if (prov.length)
            det.appendChild(el("div", { class: "f-prov" }, prov.map((p) =>
              el("div", { text: `[${p.tool_exec_id || "?"}] ${p.tool || "?"} ⇐ ${p.raw_locator || "—"}` + (p.note ? `  · ${p.note}` : "") }))));
          if (votes.length)
            det.appendChild(el("div", { style: { marginTop: prov.length ? "8px" : "0", display: "grid", gap: "4px" } },
              votes.map((v) => el("div", { class: "muted", style: { fontSize: "12px" } }, [
                el("b", { class: "mono", style: { color: "var(--accent-2)" }, text: v.perspective || "?" }),
                el("span", { text: ": " }),
                badge(v.vote || "?", v.vote === "UPHOLD" ? "good" : v.vote === "REFUTE" ? "bad" : "ghost"),
                el("span", { class: "faint", style: { marginLeft: "6px" }, text: v.reason || "" }),
              ]))));
          kids.push(det);
        }

        return el("div", { class: "card sev-rail finding " + k }, kids);
      }

      function renderList() {
        const sevOrder = (s) => { const i = SEV.indexOf(String(s || "INFO").toUpperCase()); return i < 0 ? SEV.length : i; };
        const rows = findings.filter(matches).sort((a, b) => {
          const d = sevOrder(a.severity) - sevOrder(b.severity);
          if (d) return d;
          return (b.confidence_score || 0) - (a.confidence_score || 0);
        });

        list.innerHTML = "";
        count.textContent = `${rows.length} of ${findings.length} finding${findings.length === 1 ? "" : "s"}`;

        if (!rows.length) { list.appendChild(empty("No findings match these filters")); return; }
        rows.forEach((f) => list.appendChild(fcard(f)));
      }

      /* ---- wire filters (re-render list only) ---- */
      sevSel.addEventListener("change", () => { filters.sev = sevSel.value; renderList(); });
      verdictSel.addEventListener("change", () => { filters.verdict = verdictSel.value; renderList(); });
      search.addEventListener("input", () => { filters.q = search.value.trim().toLowerCase(); renderList(); });

      renderList();
    },
  });
})();
