/* Sets the saved theme before first paint to avoid a flash of the wrong theme.
   Kept as an external file so the page can ship a strict CSP (script-src 'self',
   no 'unsafe-inline'). Loaded render-blocking in <head>. */
(function () {
  try {
    var t = localStorage.getItem("glassbox-theme");
    if (!t) t = (window.matchMedia && matchMedia("(prefers-color-scheme: light)").matches) ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", t);
  } catch (e) {
    document.documentElement.setAttribute("data-theme", "dark");
  }
})();
