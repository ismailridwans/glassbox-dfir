/* Boots the SPA once all view scripts have registered. External (not inline) so
   the page can ship a strict CSP with script-src 'self' and no 'unsafe-inline'.
   DOMContentLoaded fires after every synchronous <script> above has executed, so
   all views are registered by the time boot() runs. */
window.addEventListener("DOMContentLoaded", function () { GLASSBOX.boot(); });
