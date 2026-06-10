/* GLASSBOX landing — live terminal, tool marquee, pipeline, theme toggle, reveal-on-scroll. */
(function () {
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

  const TOOLS = ["Volatility 3", "The Sleuth Kit", "Hayabusa", "EvtxECmd", "tshark",
    "RegRipper", "YARA", "Plaso", "MFTECmd", "bulk_extractor", "python-evtx", "Sigma"];

  const TERM = [
    '<span class="p">$</span> glassbox triage /cases/incident-001',
    '<span class="tag">[intake]</span>    <span class="dim">3 evidence items hashed · integrity baseline set</span>',
    '<span class="tag">[plan]</span>      iter 1 · 13 read-only tools queued',
    '<span class="tag">[collect]</span>   memory · disk · evtx · pcap  <span class="dim">→</span>  35 findings',
    '<span class="tag">[correlate]</span> hidden process PID 1520 <span class="dim">(psscan ≠ pslist)</span>',
    '<span class="tag">[verify]</span>    36 confirmed · <span class="bad">1 hallucinated → quarantined</span>',
    '<span class="tag">[red-team]</span>  41 upheld · 20 demoted · <span class="bad">3 refuted</span>',
    '<span class="tag">[critique]</span>  gap found <span class="dim">→</span> re-running psscan, malfind',
    '<span class="tag">[report]</span>    <span class="ok">triage complete in 0.46s · audit chain VALID</span>',
    '<span class="ok">✓</span> every finding traces to a tool call',
  ];

  function buildPipe() {
    const pipe = document.getElementById("pipe");
    if (pipe) STEPS.forEach((s) => {
      const d = document.createElement("div");
      d.className = "pstep" + (s.hot ? " hot" : "");
      d.innerHTML = `<div class="n">${s.n}</div><h4>${s.t}</h4><p>${s.p}</p>`;
      pipe.appendChild(d);
    });
  }

  function buildMarquee() {
    const m = document.getElementById("marquee");
    if (!m) return;
    const items = TOOLS.concat(TOOLS); // duplicate for a seamless loop
    m.innerHTML = items.map((t) => `<span class="marquee-item"><span class="d"></span>${t}</span>`).join("");
  }

  function runTerminal() {
    const term = document.getElementById("term");
    if (!term) return;
    const cursor = '<span class="term-cursor"></span>';
    let i = 0;
    function step() {
      term.innerHTML = TERM.slice(0, i).map((l) => `<div class="term-line">${l}</div>`).join("")
        + `<div class="term-line">${cursor}</div>`;
      i++;
      if (i <= TERM.length) {
        setTimeout(step, i === 1 ? 450 : 240 + Math.random() * 280);
      } else {
        term.innerHTML = TERM.map((l) => `<div class="term-line">${l}</div>`).join("")
          + `<div class="term-line"><span class="p">$</span> ${cursor}</div>`;
        setTimeout(() => { i = 0; step(); }, 5600); // loop for a "live" feel
      }
    }
    step();
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
    }, { threshold: 0.1 });
    els.forEach((e) => io.observe(e));
  }

  window.addEventListener("DOMContentLoaded", () => { buildPipe(); buildMarquee(); runTerminal(); theme(); reveal(); });
})();
