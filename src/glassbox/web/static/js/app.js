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
    const track = getComputedStyle(document.documentElement).getPropertyValue("--elevated").trim() || "#16203a";
    svg.appendChild(ring(track, 1, `${C} 0`));
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

  /* line sparkline from an array of numbers */
  function sparkline(values, opts = {}) {
    const w = opts.width || 120, h = opts.height || 34, pad = 2;
    const v = (values && values.length) ? values : [0, 0];
    const min = Math.min(...v), max = Math.max(...v), span = (max - min) || 1;
    const stepX = (w - pad * 2) / Math.max(1, v.length - 1);
    const pts = v.map((y, i) => [pad + i * stepX, h - pad - ((y - min) / span) * (h - pad * 2)]);
    const color = opts.color || getComputedStyle(document.documentElement).getPropertyValue("--brand").trim();
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", `0 0 ${w} ${h}`); svg.setAttribute("width", opts.fullWidth ? "100%" : w);
    svg.setAttribute("height", h); svg.setAttribute("class", "spark"); svg.setAttribute("preserveAspectRatio", "none");
    if (opts.fill) {
      const area = document.createElementNS(ns, "path");
      area.setAttribute("d", `M${pts[0][0]},${h} ` + pts.map((p) => `L${p[0]},${p[1]}`).join(" ") + ` L${pts[pts.length-1][0]},${h} Z`);
      area.setAttribute("fill", color); area.setAttribute("opacity", "0.12"); svg.appendChild(area);
    }
    const line = document.createElementNS(ns, "polyline");
    line.setAttribute("points", pts.map((p) => p.join(",")).join(" "));
    line.setAttribute("fill", "none"); line.setAttribute("stroke", color);
    line.setAttribute("stroke-width", opts.weight || 1.8); line.setAttribute("stroke-linecap", "round");
    line.setAttribute("stroke-linejoin", "round"); line.setAttribute("vector-effect", "non-scaling-stroke");
    svg.appendChild(line);
    return svg;
  }

  /* interactive area chart with hover tooltip — the signature dashboard element.
     points = [{label, value}]; opts: {height, color, valueFmt, fullWidth} */
  let _chartSeq = 0;
  function cssVar(n) { return getComputedStyle(document.documentElement).getPropertyValue(n).trim(); }
  function areaChart(points, opts = {}) {
    const W = 760, H = opts.height || 240, padL = 30, padR = 14, padT = 16, padB = 30;
    const ns = "http://www.w3.org/2000/svg";
    const wrap = el("div", { style: { position: "relative", width: "100%" } });
    if (!points || !points.length) { wrap.appendChild(empty("No data")); return wrap; }
    const n = points.length;
    const maxV = Math.max(1, ...points.map((p) => p.value));
    const plotW = W - padL - padR, plotH = H - padT - padB;
    const xAt = (i) => padL + (n <= 1 ? plotW / 2 : (i / (n - 1)) * plotW);
    const yAt = (v) => padT + plotH - (v / maxV) * plotH;
    const color = opts.color || cssVar("--brand");
    const id = "gc" + (++_chartSeq);

    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", `0 0 ${W} ${H}`); svg.setAttribute("width", "100%");
    svg.setAttribute("height", H); svg.setAttribute("preserveAspectRatio", "none"); svg.style.display = "block";
    svg.innerHTML = `<defs><linearGradient id="${id}" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="${color}" stop-opacity="0.26"/><stop offset="1" stop-color="${color}" stop-opacity="0"/></linearGradient></defs>`;

    // horizontal gridlines + y labels
    for (let g = 0; g <= 4; g++) {
      const gy = padT + (g / 4) * plotH;
      const gl = document.createElementNS(ns, "line");
      gl.setAttribute("x1", padL); gl.setAttribute("x2", W - padR); gl.setAttribute("y1", gy); gl.setAttribute("y2", gy);
      gl.setAttribute("stroke", cssVar("--border")); gl.setAttribute("stroke-width", "1"); gl.setAttribute("vector-effect", "non-scaling-stroke");
      svg.appendChild(gl);
    }
    const lp = points.map((p, i) => [xAt(i), yAt(p.value)]);
    const area = document.createElementNS(ns, "path");
    area.setAttribute("d", `M${lp[0][0]},${padT + plotH} ` + lp.map((p) => `L${p[0]},${p[1]}`).join(" ") + ` L${lp[n - 1][0]},${padT + plotH} Z`);
    area.setAttribute("fill", `url(#${id})`); svg.appendChild(area);
    const line = document.createElementNS(ns, "polyline");
    line.setAttribute("points", lp.map((p) => p.join(",")).join(" "));
    line.setAttribute("fill", "none"); line.setAttribute("stroke", color); line.setAttribute("stroke-width", "2.4");
    line.setAttribute("stroke-linecap", "round"); line.setAttribute("stroke-linejoin", "round"); line.setAttribute("vector-effect", "non-scaling-stroke");
    svg.appendChild(line);
    // x labels
    points.forEach((p, i) => {
      if (n > 8 && i % 2 !== 0 && i !== n - 1) return;
      const tx = document.createElementNS(ns, "text");
      tx.setAttribute("x", xAt(i)); tx.setAttribute("y", H - 8); tx.setAttribute("text-anchor", "middle");
      tx.setAttribute("font-size", "10"); tx.setAttribute("fill", cssVar("--faint"));
      tx.textContent = String(p.label).slice(0, 6); svg.appendChild(tx);
    });
    // hover elements
    const guide = document.createElementNS(ns, "line");
    guide.setAttribute("stroke", color); guide.setAttribute("stroke-width", "1"); guide.setAttribute("vector-effect", "non-scaling-stroke");
    guide.setAttribute("y1", padT); guide.setAttribute("y2", padT + plotH); guide.style.opacity = "0"; svg.appendChild(guide);
    const dot = document.createElementNS(ns, "circle");
    dot.setAttribute("r", "4.5"); dot.setAttribute("fill", color); dot.setAttribute("stroke", cssVar("--surface")); dot.setAttribute("stroke-width", "2");
    dot.style.opacity = "0"; svg.appendChild(dot);
    wrap.appendChild(svg);

    const tip = el("div", { style: {
      position: "absolute", pointerEvents: "none", opacity: "0", transform: "translate(-50%,-120%)",
      background: cssVar("--elevated"), border: "1px solid " + cssVar("--border-hi"), borderRadius: "9px",
      padding: "7px 11px", fontSize: "12px", whiteSpace: "nowrap", boxShadow: cssVar("--shadow-sm"), transition: "opacity .1s", zIndex: "5" } });
    wrap.appendChild(tip);

    const fmt = opts.valueFmt || ((v) => v);
    svg.addEventListener("mousemove", (e) => {
      const r = svg.getBoundingClientRect();
      const vbx = ((e.clientX - r.left) / r.width) * W;
      let i = Math.round(((vbx - padL) / plotW) * (n - 1));
      i = Math.max(0, Math.min(n - 1, i));
      const px = xAt(i), py = yAt(points[i].value);
      guide.setAttribute("x1", px); guide.setAttribute("x2", px); guide.style.opacity = ".5";
      dot.setAttribute("cx", px); dot.setAttribute("cy", py); dot.style.opacity = "1";
      tip.innerHTML = `<b style="font-family:var(--mono)">${fmt(points[i].value)}</b> <span class="faint">${esc(points[i].label)}</span>`;
      tip.style.left = ((px / W) * r.width) + "px";
      tip.style.top = ((py / H) * r.height) + "px";
      tip.style.opacity = "1";
    });
    svg.addEventListener("mouseleave", () => { guide.style.opacity = "0"; dot.style.opacity = "0"; tip.style.opacity = "0"; });
    return wrap;
  }

  /* fintech-style bar sparkline: `filled` of n bars colored, rest faint */
  function sparkbars(n, filled, color) {
    const wrap = el("div", { class: "sparkbars" });
    const c = color || getComputedStyle(document.documentElement).getPropertyValue("--brand").trim();
    for (let i = 0; i < n; i++) {
      const bar = el("i");
      const hpct = 35 + Math.round(((Math.sin(i * 1.7) + 1) / 2) * 55) + (i % 3 === 0 ? 10 : 0);
      bar.style.height = Math.min(100, hpct) + "%";
      if (i < filled) bar.style.background = c;
      wrap.appendChild(bar);
    }
    return wrap;
  }

  /* segmented control: options=[{label,value}] or [str]; onChange(value) */
  function segmented(options, active, onChange) {
    const seg = el("div", { class: "seg" });
    options.forEach((o) => {
      const val = o.value != null ? o.value : o;
      const lab = o.label != null ? o.label : o;
      const b = el("button", { class: "seg-btn" + (val === active ? " active" : ""), text: lab,
        onclick: () => { seg.querySelectorAll(".seg-btn").forEach((x) => x.classList.remove("active")); b.classList.add("active"); onChange && onChange(val); } });
      seg.appendChild(b);
    });
    return seg;
  }

  /* up/down trend pill */
  function trend(value, opts = {}) {
    const up = Number(value) >= 0;
    return el("span", { class: "trend " + (up ? "up" : "down") }, [
      el("span", { class: "car", text: up ? "▲" : "▼" }),
      (up ? "+" : "") + value + (opts.suffix || ""),
    ]);
  }

  function skeleton(h = 16, w = "100%") { return el("div", { class: "skel", style: { height: h + "px", width: w } }); }

  G.ui = { el, frag, esc, card, stat, badge, sevBadge, pill, table, empty, donut, legend, bars,
           sparkline, sparkbars, areaChart, segmented, trend, skeleton, cssVar,
           sevKey, sevColor, SEV, fmtNum: (n) => (n == null ? "—" : Number(n).toLocaleString()) };

  /* ---------------- theme ---------------- */
  const THEME_KEY = "glassbox-theme";
  function applyTheme(t) {
    document.documentElement.setAttribute("data-theme", t);
    try { localStorage.setItem(THEME_KEY, t); } catch (e) {}
  }
  function initTheme() {
    let t;
    try { t = localStorage.getItem(THEME_KEY); } catch (e) {}
    if (!t) t = (window.matchMedia && matchMedia("(prefers-color-scheme: light)").matches) ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", t);
    return t;
  }
  G.theme = {
    get: () => document.documentElement.getAttribute("data-theme") || "dark",
    set: applyTheme,
    toggle: () => applyTheme(G.theme.get() === "dark" ? "light" : "dark"),
  };

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
    initTheme();
    document.getElementById("run-btn").addEventListener("click", runTriage);
    const app = document.getElementById("app");
    const isMobile = () => window.matchMedia("(max-width: 900px)").matches;
    document.getElementById("menu-toggle").addEventListener("click", () =>
      app.classList.toggle(isMobile() ? "show-nav" : "collapsed"));
    // mobile drawer: tap the scrim or a nav link to close
    app.addEventListener("click", (e) => {
      if (!isMobile() || !app.classList.contains("show-nav")) return;
      if (e.target === app || e.target.closest(".nav-item")) app.classList.remove("show-nav");
    });
    const tt = document.getElementById("theme-toggle");
    if (tt) tt.addEventListener("click", () => { G.theme.toggle(); render(currentId()); });
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
