/* GLASSBOX API client — thin fetch + EventSource wrapper. */
(function () {
  async function getJSON(path) {
    const res = await fetch(path, { headers: { Accept: "application/json" } });
    if (!res.ok) throw new Error(`${path} → ${res.status}`);
    return res.json();
  }

  const API = {
    state:      () => getJSON("/api/state"),
    report:     () => getJSON("/api/report"),
    a2a:        () => getJSON("/api/a2a"),
    navigator:  () => getJSON("/api/navigator"),
    diamond:    () => getJSON("/api/diamond"),
    speed:      () => getJSON("/api/speed"),
    audit:      () => getJSON("/api/audit"),
    guardrail:  () => getJSON("/api/guardrail"),
    replay:     () => getJSON("/api/replay"),

    /* SSE live triage. onEvent(evt) called per event; returns the EventSource. */
    streamTriage(onEvent, onDone, onError) {
      const es = new EventSource("/api/triage/stream");
      es.onmessage = (m) => {
        let data;
        try { data = JSON.parse(m.data); } catch { return; }
        if (data.type === "done") { onEvent && onEvent(data); es.close(); onDone && onDone(data); }
        else if (data.type === "error") { es.close(); onError && onError(data); }
        else { onEvent && onEvent(data); }
      };
      es.onerror = () => { es.close(); onError && onError({ error: "stream closed" }); };
      return es;
    },
  };

  window.GLASSBOX = window.GLASSBOX || {};
  window.GLASSBOX.api = API;
})();
