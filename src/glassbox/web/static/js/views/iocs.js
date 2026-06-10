/* IOC Explorer — indicators of compromise, grouped by type, all DEFANGED.
 * Contract: GLASSBOX.registerView(id, { title, sub, order, icon, badge?, render }).
 * render(root, ctx): build DOM into `root`. ctx = { state, report, api, ui, go, refresh }.
 * Consumes ctx.report.iocs : [{ type, value, defanged, context, provenance:[{tool_exec_id,...}] }].
 */
(function () {
  const ICON = "<svg viewBox='0 0 24 24'><circle cx='11' cy='11' r='7' fill='none' stroke='currentColor' stroke-width='1.6'/><path d='M16 16l5 5' stroke='currentColor' stroke-width='1.6' stroke-linecap='round'/><path d='M11 8v3.5l2.2 2.2' stroke='currentColor' stroke-width='1.4' stroke-linecap='round' stroke-linejoin='round' fill='none'/></svg>";

  // Canonical display order + human labels for the IOC types we know about.
  const TYPES = [
    ["ipv4",     "IPv4 Addresses"],
    ["ipv6",     "IPv6 Addresses"],
    ["domain",   "Domains"],
    ["url",      "URLs"],
    ["filepath", "File Paths"],
    ["sha256",   "SHA-256 Hashes"],
    ["md5",      "MD5 Hashes"],
    ["email",    "Email Addresses"],
    ["regpath",  "Registry Paths"],
  ];

  const COPY_IC = "<svg viewBox='0 0 24 24' width='14' height='14'><rect x='9' y='9' width='11' height='11' rx='2' fill='none' stroke='currentColor' stroke-width='1.6'/><path d='M5 15V5a2 2 0 0 1 2-2h8' fill='none' stroke='currentColor' stroke-width='1.6' stroke-linecap='round'/></svg>";

  /* Copy text to clipboard, degrading gracefully on older / insecure contexts.
   * Returns a Promise<boolean> indicating success. Never throws. */
  function copyText(text) {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        return navigator.clipboard.writeText(text).then(() => true, () => fallbackCopy(text));
      }
    } catch (_) { /* fall through */ }
    return Promise.resolve(fallbackCopy(text));
  }
  function fallbackCopy(text) {
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.top = "-1000px";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand("copy");
      document.body.removeChild(ta);
      return ok;
    } catch (_) { return false; }
  }

  // Flash a button's label, then restore it (visual confirmation of a copy).
  function flash(btn, msg) {
    const prev = btn.dataset.label != null ? btn.dataset.label : btn.textContent;
    btn.dataset.label = prev;
    btn.textContent = msg;
    btn.classList.add("ok");
    clearTimeout(btn._flashT);
    btn._flashT = setTimeout(() => { btn.textContent = btn.dataset.label; btn.classList.remove("ok"); }, 1200);
  }

  GLASSBOX.registerView("iocs", {
    title: "IOCs",
    sub: "indicators of compromise — defanged",
    order: 60,
    icon: ICON,
    badge: (ctx) => ((ctx.report && ctx.report.iocs) || []).length || null,
    render(root, ctx) {
      const { ui, report: r } = ctx;
      const { el, card, stat, badge, pill, table } = ui;

      if (!r || !r.iocs) { root.appendChild(ui.empty("Run triage first")); return; }

      const iocs = (r.iocs || []).filter(Boolean);
      if (!iocs.length) {
        root.appendChild(ui.empty("No indicators of compromise extracted."));
        return;
      }

      // Group by type, preserving the canonical order; collect unknown types last.
      const groups = {};
      iocs.forEach((i) => {
        const t = String(i.type || "other").toLowerCase();
        (groups[t] = groups[t] || []).push(i);
      });
      const known = TYPES.filter(([k]) => groups[k] && groups[k].length);
      const extra = Object.keys(groups)
        .filter((k) => !TYPES.some(([t]) => t === k))
        .sort()
        .map((k) => [k, k.toUpperCase()]);
      const ordered = known.concat(extra);

      const defangedOf = (i) => (i.defanged != null && i.defanged !== "") ? i.defanged : i.value;
      const srcOf = (i) => {
        const p = (i.provenance || [])[0] || {};
        return p.tool_exec_id || "—";
      };

      /* ---- prominent DEFANGED safety notice ---- */
      root.appendChild(el("div", { class: "card", style: {
        marginBottom: "16px", borderLeft: "3px solid var(--accent)",
        display: "flex", gap: "12px", alignItems: "center", padding: "12px 16px",
      } }, [
        el("span", { class: "nav-ic", style: { color: "var(--accent)" }, html:
          "<svg viewBox='0 0 24 24' width='22' height='22'><path d='M12 3l8 3v5c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6l8-3z' fill='none' stroke='currentColor' stroke-width='1.5' stroke-linejoin='round'/><path d='M9 12l2 2 4-4' fill='none' stroke='currentColor' stroke-width='1.6' stroke-linecap='round' stroke-linejoin='round'/></svg>" }),
        el("div", {}, [
          el("b", { text: "All indicators are DEFANGED for safe handling." }),
          el("div", { class: "muted", style: { fontSize: "12.5px", marginTop: "2px" },
            html: "URLs use <span class='mono'>hxxp</span> and dots are bracketed <span class='mono'>[.]</span> so values cannot be accidentally clicked, resolved, or detonated. Re-fang only inside an isolated analysis environment." }),
        ]),
      ]));

      /* ---- stat tiles: total + per-type counts ---- */
      const tiles = [ stat("Total IOCs", ui.fmtNum(iocs.length), { tone: "accent", foot: `${ordered.length} distinct type(s)` }) ];
      ordered.forEach(([k, label]) => tiles.push(stat(label, ui.fmtNum(groups[k].length), { foot: k })));
      root.appendChild(el("div", { class: "grid cols-4", style: { marginBottom: "16px" } }, tiles));

      /* ---- toolbar: copy all (defanged) ---- */
      const copyAllBtn = el("button", { class: "btn btn-primary btn-sm", html:
        COPY_IC + "<span style='margin-left:6px'>Copy all (defanged)</span>",
        onclick: function () {
          const txt = iocs.map(defangedOf).join("\n");
          copyText(txt).then((ok) => flash(this, ok ? `Copied ${iocs.length}` : "Copy failed"));
        } });
      root.appendChild(el("div", { class: "toolbar" }, [
        el("span", { class: "muted", style: { fontSize: "12.5px" },
          text: `${iocs.length} indicator(s) across ${ordered.length} type(s)` }),
        el("span", { class: "spacer" }),
        copyAllBtn,
      ]));

      /* ---- one card per non-empty type ---- */
      ordered.forEach(([k, label]) => {
        const rows = groups[k];

        const columns = [
          { label: "Value (defanged)", mono: true, render: (i) => defangedOf(i) },
          { label: "Context", render: (i) =>
              (i.context && i.context !== "")
                ? el("span", { class: "muted", style: { fontSize: "12.5px" }, text: i.context })
                : el("span", { class: "faint", text: "—" }) },
          { label: "Source", render: (i) => el("span", { class: "pill", text: srcOf(i) }) },
          { label: "", render: (i) => {
              const b = el("button", { class: "btn btn-ghost btn-sm", title: "Copy this value (defanged)",
                html: COPY_IC,
                onclick: function () { copyText(defangedOf(i)).then((ok) => flash(this, ok ? "✓" : "✗")); } });
              return el("div", { class: "row", style: { justifyContent: "flex-end" } }, b);
            } },
        ];

        root.appendChild(card(label, table(columns, rows), {
          sub: `${rows.length} indicator(s)`,
          action: badge(k, "mono"),
          class: "ioc-group",
          bodyClass: "pad-0",
        }));
      });
    },
  });
})();
