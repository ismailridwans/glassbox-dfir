/* GLASSBOX landing page — populates feature grid + pipeline, theme toggle, reveal-on-scroll. */
(function () {
  const FEATURES = [
    { ic: "M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z|M9 12l2 2 4-4",
      t: "Read-only by construction", p: "The MCP server exposes only typed read functions. There is no shell, write, or delete tool for the agent to call — so it cannot modify evidence.", tag: "architectural" },
    { ic: "M5 12l4 4L19 6",
      t: "Mechanical hallucination gate", p: "Every finding is re-checked against the captured raw output of the tool it cites. Ungrounded claims are quarantined, never reported as fact.", tag: "0 false claims" },
    { ic: "M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z",
      t: "Adversarial red-team", p: "A panel of skeptic perspectives challenges every grounded finding — upheld, demoted, or refuted — removing false positives like benign public DNS.", tag: "tiebreaker" },
    { ic: "M7 7l-4 5 4 5M17 7l4 5-4 5M14 4l-4 16",
      t: "Cross-source correlation", p: "Compares disk vs memory to surface hidden processes (psscan vs pslist), orphan connections, and bad parents that single-source analysis misses.", tag: "disk × memory" },
    { ic: "M4 7h16M4 12h16M4 17h10",
      t: "Hash-chained audit trail", p: "A tamper-evident chain of custody. Each record's hash covers the prior — any edit, insertion or deletion is detected on re-verify.", tag: "chain of custody" },
    { ic: "M3.5 3.5h7v7h-7zM13.5 3.5h7v4h-7zM13.5 11h7v9.5h-7zM3.5 13h7v7.5h-7z",
      t: "Full ATT&CK kill-chain", p: "Maps findings across the kill chain with verified technique IDs, and exports a Navigator layer that loads in the official MITRE tool.", tag: "27 techniques" },
    { ic: "M3 12a9 9 0 109-9|M12 3v5l3 2",
      t: "Court-admissible replay", p: "The entire finding set re-derives from the audit log + captured output, proving reproducibility — the bedrock of forensic defensibility.", tag: "FRE 901 / Daubert" },
    { ic: "M4 4v6h6|M20 20v-6h-6|M4 10a8 8 0 0114-3M20 14a8 8 0 01-14 3",
      t: "Bounded self-correction", p: "When the agent spots a gap it re-plans and re-runs — bounded by a hard max-iterations counter in code, so it can never spiral.", tag: "autonomous" },
  ];
  const STEPS = [
    { n: "01", t: "Intake", p: "Hash evidence, set integrity baseline" },
    { n: "02", t: "Plan", p: "Sequence read-only tools like an analyst" },
    { n: "03", t: "Collect", p: "Specialist agents per evidence type" },
    { n: "04", t: "Correlate", p: "Disk-vs-memory discrepancies" },
    { n: "05", t: "ATT&CK", p: "Map the full kill chain" },
    { n: "06", t: "Verify", p: "Hallucination gate", hot: true },
    { n: "07", t: "Red-team", p: "Adversarial panel", hot: true },
    { n: "08", t: "Self-correct", p: "Loop on gaps (bounded)" },
    { n: "09", t: "Report", p: "Cited, court-admissible" },
  ];

  function svgIc(spec) {
    const paths = spec.split("|").map((d) =>
      `<path d="${d}" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/>`).join("");
    return `<svg viewBox="0 0 24 24" width="20" height="20">${paths}</svg>`;
  }

  function build() {
    const fg = document.getElementById("feat-grid");
    if (fg) FEATURES.forEach((f) => {
      const d = document.createElement("div");
      d.className = "feat reveal";
      d.innerHTML = `<div class="fi">${svgIc(f.ic)}</div><h3>${f.t}</h3><p>${f.p}</p><span class="tag">${f.tag}</span>`;
      fg.appendChild(d);
    });
    const pipe = document.getElementById("pipe");
    if (pipe) STEPS.forEach((s) => {
      const d = document.createElement("div");
      d.className = "pstep" + (s.hot ? " hot" : "");
      d.innerHTML = `<div class="n">${s.n}</div><h4>${s.t}</h4><p>${s.p}</p>`;
      pipe.appendChild(d);
    });
  }

  function theme() {
    const KEY = "glassbox-theme";
    const get = () => document.documentElement.getAttribute("data-theme") || "dark";
    const set = (t) => { document.documentElement.setAttribute("data-theme", t); try { localStorage.setItem(KEY, t); } catch (e) {} };
    const btn = document.getElementById("theme-toggle");
    if (btn) btn.addEventListener("click", () => set(get() === "dark" ? "light" : "dark"));
  }

  function reveal() {
    const els = document.querySelectorAll(".reveal");
    if (!("IntersectionObserver" in window)) { els.forEach((e) => e.classList.add("in")); return; }
    const io = new IntersectionObserver((entries) => {
      entries.forEach((en) => { if (en.isIntersecting) { en.target.classList.add("in"); io.unobserve(en.target); } });
    }, { threshold: 0.12 });
    els.forEach((e) => io.observe(e));
  }

  window.addEventListener("DOMContentLoaded", () => { build(); theme(); reveal(); });
})();
