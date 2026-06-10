/* GLASSBOX SPA framework: view registry, router, shared UI helpers.
 *
 * A view registers itself:
 *   GLASSBOX.registerView("findings", {
 *     title: "Findings", sub: "...", order: 30, icon: "<svg…>",
 *     badge: (ctx) => ctx.report.findings?.length,     // optional sidebar count
 *     render: async (root, ctx) => { ... }             // build into `root`
 *   });
 *
 * render() receives ctx = { state, report, api, ui, refresh, go }.
 * ui = the helper toolkit below (el, card, badge, sev, table, donut, …).
 */
(function () {
  const G = (window.GLASSBOX = window.GLASSBOX || {});
  const views = {};
  G.registerView = (id, def) => { views[id] = Object.assign({ id }, def); };

  /* ---------------- UI helpers ---------------- */
  function el(tag, attrs, children) {
    const n = document.createElement(tag);
    if (attrs) for (const [k, v] of Object.entries(attrs)) {
      if (v == null) continue;
      if (k === "class") n.className = v;
      else if (k === "html") n.innerHTML = v;
      else if (k === "text") n.textContent = v;
      else if (k.startsWith("on") && typeof v === "function") n.addEventListener(k.slice(2), v);
      else if (k === "style" && typeof v === "object") Object.assign(n.style, v);
      else n.setAttribute(k, v);
    }
    if (children != null) (Array.isArray(children) ? children : [children]).forEach((c) => {
      if (c == null) return;
      n.appendChild(typeof c === "string" || typeof c === "number" ? document.createTextNode(String(c)) : c);
    });
    return n;
  }
  const frag = (...kids) => { const f = document.createDocumentFragment(); kids.flat().forEach((k) => k && f.appendChild(k)); return f; };
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;" }[c]));

  const SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  const sevKey = (s) => ({ CRITICAL:"crit", HIGH:"high", MEDIUM:"med", LOW:"low", INFO:"info" }[String(s||"INFO").toUpperCase()] || "info");
  const sevColor = (s) => getComputedStyle(document.documentElement).getPropertyValue("--" + sevKey(s)).trim() || "#64748b";

  function card(title, body, opts = {}) {
    const head = title ? el("div", { class: "card-head" }, [
      el("h3", { text: title }),
      opts.sub ? el("span", { class: "sub", text: opts.sub }) : null,
      opts.action || null,
    ]) : null;
    return el("div", { class: "card " + (opts.class || "") }, [
      head,
      el("div", { class: "card-body " + (opts.bodyClass || "") }, body),
    ]);
  }
  function stat(label, value, opts = {}) {
    return el("div", { class: "card stat " + (opts.tone || "") }, [
      el("div", { class: "stat-label", text: label }),
      el("div", { class: "stat-value", text: value }),
      opts.foot ? el("div", { class: "stat-foot", html: opts.foot }) : null,
    ]);
  }
  function badge(text, kind = "ghost") { return el("span", { class: "badge " + kind, text }); }
  function sevBadge(s) { return el("span", { class: "badge " + sevKey(s), text: String(s || "INFO").toUpperCase() }); }
  function pill(text) { return el("span", { class: "pill", text }); }

  function table(columns, rows, rowAttr) {
    const thead = el("thead", {}, el("tr", {}, columns.map((c) => el("th", { text: c.label || c }))));
    const tbody = el("tbody", {}, rows.map((r) => {
      const tr = el("tr", rowAttr ? rowAttr(r) : {});
      columns.forEach((c) => {
        const key = c.key || c;
        const v = typeof c.render === "function" ? c.render(r) : r[key];
        const td = el("td", { class: c.mono ? "mono" : "" });
        if (v instanceof Node) td.appendChild(v);
        else td.innerHTML = c.html ? v : esc(v);
        tr.appendChild(td);
      });
      return tr;
    }));
    return el("div", { class: "tbl-wrap" }, el("table", { class: "tbl" }, [thead, tbody]));
  }

  function empty(msg, icon) {
    return el("div", { class: "empty" }, [
      el("div", { html: icon || "<svg viewBox='0 0 24 24' width='40' height='40'><circle cx='12' cy='12' r='9' fill='none' stroke='currentColor' stroke-width='1.4'/><path d='M8 12h8' stroke='currentColor' stroke-width='1.6' stroke-linecap='round'/></svg>" }),
      el("div", { text: msg }),
    ]);
  }

  /* donut chart from [{label,value,color}] */
  function donut(segments, opts = {}) {
    const size = opts.size || 150, r = size / 2 - 14, cx = size / 2, cy = size / 2, C = 2 * Math.PI * r;
    const total = segments.reduce((a, s) => a + (s.value || 0), 0) || 1;
    let off = 0;
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", `0 0 ${size} ${size}`); svg.setAttribute("width", size); svg.setAttribute("height", size);
    const ring = (color, frac, dash) => {
      const c = document.createElementNS(svg.namespaceURI, "circle");
      c.setAttribute("cx", cx); c.setAttribute("cy", cy); c.setAttribute("r", r);
      c.setAttribute("fill", "none"); c.setAttribute("stroke", color); c.setAttribute("stroke-width", opts.width || 14);
      c.setAttribute("stroke-dasharray", dash); c.setAttribute("stroke-dashoffset", -off * C);
      c.setAttribute("transform", `rotate(-90 ${cx} ${cy})`);
      if (opts.round) c.setAttribute("stroke-linecap", "round");
      return c;
    };
    svg.appendChild(ring("#16203a", 1, `${C} 0`));
    segments.forEach((s) => {
      const frac = (s.value || 0) / total;
      if (frac <= 0) return;
      svg.appendChild(ring(s.color, frac, `${frac * C} ${C}`));
      off += frac;
    });
    if (opts.center != null) {
      const t = document.createElementNS(svg.namespaceURI, "text");
      t.setAttribute("x", cx); t.setAttribute("y", cy); t.setAttribute("text-anchor", "middle");
      t.setAttribute("dominant-baseline", "central"); t.setAttribute("fill", "#e6edf6");
      t.setAttribute("font-size", "26"); t.setAttribute("font-weight", "800"); t.setAttribute("font-family", "var(--mono)");
      t.textContent = opts.center; svg.appendChild(t);
    }
    return svg;
  }
  function legend(segments) {
    return el("div", { class: "row wrap", style: { gap: "12px", marginTop: "10px", justifyContent: "center" } },
      segments.filter((s) => s.value).map((s) => el("span", { class: "row", style: { gap: "6px", fontSize: "12px", color: "var(--muted)" } }, [
        el("span", { style: { width: "10px", height: "10px", borderRadius: "3px", background: s.color, display: "inline-block" } }),
        `${s.label} ${s.value}`,
      ])));
  }
  /* horizontal bar list from [{label,value,color}] */
  function bars(items, opts = {}) {
    const max = Math.max(1, ...items.map((i) => i.value));
    return el("div", { class: "grid", style: { gap: "9px" } }, items.map((i) =>
      el("div", {}, [
        el("div", { class: "row", style: { justifyContent: "space-between", marginBottom: "4px", fontSize: "12.5px" } },
          [el("span", { class: "muted", text: i.label }), el("b", { class: "mono", text: String(i.value) })]),
        el("div", { class: "pbar" }, el("span", { style: { width: (100 * i.value / max) + "%", background: i.color || "linear-gradient(90deg,#22d3ee,#38bdf8)" } })),
      ])));
  }

  G.ui = { el, frag, esc, card, stat, badge, sevBadge, pill, table, empty, donut, legend, bars,
           sevKey, sevColor, SEV, fmtNum: (n) => (n == null ? "—" : Number(n).toLocaleString()) };

  /* ---------------- state + router ---------------- */
  const ctx = { state: {}, report: {}, api: G.api, ui: G.ui };
  ctx.go = (id) => { location.hash = "#/" + id; };
  ctx.refresh = async () => { await loadData(); render(currentId()); buildNav(); };

  function currentId() {
    const id = (location.hash || "").replace(/^#\/?/, "");
    return views[id] ? id : "dashboard";
  }

  async function loadData() {
    try { ctx.state = await G.api.state(); } catch { ctx.state = {}; }
    try { ctx.report = (await G.api.report()) || {}; } catch { ctx.report = {}; }
    document.getElementById("foot-case").textContent = ctx.state.case_id || "—";
    document.getElementById("foot-tools").textContent = (ctx.state.tools || []).length || "—";
    document.getElementById("foot-version").textContent = "v" + (ctx.state.version || "0.1.0");
  }

  function buildNav() {
    const nav = document.getElementById("nav");
    nav.innerHTML = "";
    Object.values(views).sort((a, b) => (a.order || 99) - (b.order || 99)).forEach((v) => {
      let count;
      try { count = v.badge ? v.badge(ctx) : null; } catch { count = null; }
      const item = el("button", { class: "nav-item" + (v.id === currentId() ? " active" : ""), onclick: () => ctx.go(v.id) }, [
        el("span", { class: "nav-ic", html: v.icon || "" }),
        el("span", { text: v.title }),
        (count != null && count !== "") ? el("span", { class: "nav-badge", text: String(count) }) : null,
      ]);
      nav.appendChild(item);
    });
  }

  async function render(id) {
    const v = views[id] || views.dashboard;
    document.getElementById("view-title").textContent = v.title || "";
    document.getElementById("view-sub").textContent = v.sub || "";
    const content = document.getElementById("content");
    content.innerHTML = "";
    content.appendChild(el("div", { class: "center", style: { padding: "40px" } }, el("span", { class: "loader" })));
    try {
      const root = el("div");
      await v.render(root, ctx);
      content.innerHTML = ""; content.appendChild(root);
    } catch (e) {
      content.innerHTML = "";
      content.appendChild(empty("View error: " + (e.message || e)));
      console.error(e);
    }
    buildNav();
  }

  /* status chip + run button */
  function setStatus(kind, text) {
    const chip = document.getElementById("status-chip");
    chip.className = "status-chip " + (kind || "");
    document.getElementById("status-text").textContent = text;
  }
  G.setStatus = setStatus;

  function runTriage() {
    // Route to the live triage view, which owns the SSE stream + UI.
    ctx.go("triage");
    setTimeout(() => { if (G.startTriage) G.startTriage(); }, 60);
  }
  G.runTriage = runTriage;

  G.boot = async function () {
    document.getElementById("run-btn").addEventListener("click", runTriage);
    document.getElementById("menu-toggle").addEventListener("click", () =>
      document.getElementById("app").classList.toggle("show-nav"));
    window.addEventListener("hashchange", () => render(currentId()));

    await loadData();
    buildNav();
    if (!ctx.state.has_report && !ctx.state.running) {
      // First visit: show the live triage immediately so judges see it work.
      setStatus("", "ready");
      ctx.go("triage");
      render("triage");
      setTimeout(() => { if (G.startTriage) G.startTriage(); }, 250);
    } else {
      setStatus(ctx.state.running ? "running" : "done", ctx.state.running ? "running" : "ready");
      render(currentId());
    }
  };
})();
