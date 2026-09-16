(() => {
  "use strict";

  const KEY_STORE = "zt_key";
  const LATE_DAYS = 7;

  const STATUS = {
    PENDING:    { label: "In attesa" },
    IN_TRANSIT: { label: "In viaggio" },
    ARRIVED:    { label: "Arrivato" },
    DELIVERED:  { label: "Ritirato" },
    RETURNED:   { label: "Rientrato vuoto" },
    NO_DATA:    { label: "Nessun dato" },
    QUEUED:     { label: "In coda tracking" },
  };
  const PENDING_STORE = "zt_pending";
  const STATUS_RANK = ["NO_DATA", "QUEUED", "PENDING", "IN_TRANSIT", "ARRIVED", "DELIVERED", "RETURNED"];
  const NUMERIC_SORT = new Set(["containers_count", "returned_count", "delay_days"]);
  const KEY_EVENTS =new Set(["LOAD", "DISCHARGE", "DELIVERY", "EMPTY_RETURN"]);

  const $ = (sel, root = document) => root.querySelector(sel);
  const state = {
    data: null, q: "", carrier: "", customer: "", status: "",
    dateField: "ship_date", dateFrom: "", dateTo: "",
    sort: "ship_date", dir: "desc", selected: null, container: 0,
    checked: new Set(),  // BL selezionati per azioni multiple
  };

  // ------------------------------------------------------------ utils
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const fmtDate = (iso) => (iso ? `${iso.slice(8, 10)}/${iso.slice(5, 7)}/${iso.slice(0, 4)}` : "—");
  const fmtDateTime = (iso) => {
    if (!iso) return "—";
    const d = new Date(iso);
    return d.toLocaleString("it-IT", { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit" });
  };
  const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const toB64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const UPPER_WORDS = new Set(["MSC", "MED", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX", "X", "XI", "XII", "USD", "HC", "DV", "PT", "CY"]);
  const title = (s) => (s || "").split(/(\s+|,\s*|-|\()/).map((w) => {
    const up = w.toUpperCase();
    if (UPPER_WORDS.has(up)) return up;
    return w.charAt(0).toUpperCase() + w.slice(1).toLowerCase();
  }).join("");
  // "RAVENNA, IT" → "Ravenna, IT" · "JAKARTA, JAVA, ID" → "Jakarta, Java, ID"
  const place = (s) => {
    const parts = (s || "").split(",").map((p) => p.trim()).filter(Boolean);
    if (parts.length > 1 && /^[A-Za-z]{2}$/.test(parts[parts.length - 1])) {
      return [...parts.slice(0, -1).map(title), parts[parts.length - 1].toUpperCase()].join(", ");
    }
    return title(s);
  };
  const port = (s) => title((s || "").split(",")[0]);
  const badge = (st) => `<span class="badge st-${esc(st)}">${esc(STATUS[st]?.label || st)}</span>`;
  const isOpen = (s) => s.status !== "RETURNED";
  const isLate = (s) => isOpen(s) && s.delay_days != null && s.delay_days > LATE_DAYS;

  function delayHtml(d) {
    if (d == null) return '<span class="muted">—</span>';
    const cls = d > LATE_DAYS ? "delay-bad" : d > 0 ? "delay-warn" : "delay-ok";
    return `<span class="${cls}">${d > 0 ? "+" : ""}${d} gg</span>`;
  }

  function trackingUrl(s) {
    return s.carrier === "MAERSK"
      ? `https://www.maersk.com/tracking/${encodeURIComponent(s.bl.replace(/^MAEU/, ""))}`
      : `https://www.msc.com/en/track-a-shipment?trackingNumber=${encodeURIComponent(s.bl)}&trackingMode=0`;
  }

  // ------------------------------------------------------------ crypto
  async function deriveKey(password, payload) {
    const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", hash: "SHA-256", salt: b64(payload.salt), iterations: payload.iter },
      base, { name: "AES-GCM", length: 256 }, true, ["decrypt"]
    );
  }

  async function decrypt(key, payload) {
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(payload.iv) }, key, b64(payload.ct));
    return JSON.parse(new TextDecoder().decode(plain));
  }

  function storage(remember) {
    try { return remember ? localStorage : sessionStorage; } catch { return null; }
  }

  async function saveKey(key, remember) {
    const raw = toB64(await crypto.subtle.exportKey("raw", key));
    const value = JSON.stringify({ k: raw, salt: window.ZT_ENCRYPTED.salt });
    try { (remember ? localStorage : sessionStorage).setItem(KEY_STORE, value); } catch { /* storage non disponibile */ }
  }

  function clearKey() {
    for (const s of [storage(true), storage(false)]) { try { s?.removeItem(KEY_STORE); } catch { /* */ } }
  }

  async function tryStoredKey() {
    for (const s of [storage(false), storage(true)]) {
      try {
        const saved = JSON.parse(s?.getItem(KEY_STORE) || "null");
        if (!saved || saved.salt !== window.ZT_ENCRYPTED.salt) continue;
        const key = await crypto.subtle.importKey("raw", b64(saved.k), "AES-GCM", false, ["decrypt"]);
        const data = await decrypt(key, window.ZT_ENCRYPTED);
        state.key = key;
        return data;
      } catch { /* chiave non valida: si passa al login */ }
    }
    return null;
  }

  // ------------------------------------------------------------ login
  async function init() {
    if (!window.ZT_ENCRYPTED) {
      showLogin("Dati non trovati. Eseguire l'aggiornamento del tracking.");
      return;
    }
    if (!window.crypto?.subtle) {
      showLogin("Il browser non supporta la decifratura: aprire il portale tramite https o http://localhost.");
      return;
    }
    const data = await tryStoredKey();
    if (data) start(data); else showLogin();
  }

  function showLogin(message) {
    $("#app").hidden = true;
    $("#login").hidden = false;
    const err = $("#login-error");
    err.hidden = !message;
    err.textContent = message || "";
    $("#password").focus();
  }

  $("#login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = $("#login-btn");
    const err = $("#login-error");
    btn.disabled = true;
    btn.textContent = "Verifica…";
    err.hidden = true;
    try {
      const key = await deriveKey($("#password").value, window.ZT_ENCRYPTED);
      const data = await decrypt(key, window.ZT_ENCRYPTED);
      await saveKey(key, $("#remember").checked);
      state.key = key;
      $("#password").value = "";
      start(data);
    } catch {
      err.textContent = "Password errata.";
      err.hidden = false;
      $("#password").select();
    } finally {
      btn.disabled = false;
      btn.textContent = "Accedi";
    }
  });

  $("#logout-btn").addEventListener("click", () => {
    clearKey();
    clearTimeout(refresh.timer);
    state.data = null;
    state.key = null;
    closeDrawer();
    showLogin();
  });

  // ------------------------------------------------------------ app
  function start(data) {
    state.data = data;
    $("#login").hidden = true;
    $("#app").hidden = false;
    $("#updated").textContent = `Aggiornato il ${fmtDateTime(data.generated_at)}`;

    const fill = (sel, values, current) => {
      const el = $(sel);
      el.length = 1;
      [...new Set(values.filter(Boolean))].sort().forEach((v) => el.add(new Option(title(v), v)));
      el.value = current;
    };
    fill("#f-carrier", data.shipments.map((s) => s.carrier), state.carrier);
    fill("#f-customer", data.shipments.map((s) => s.customer), state.customer);
    $("#customers").innerHTML = [...new Set(data.shipments.map((s) => s.customer).filter(Boolean))].sort()
      .map((c) => `<option value="${esc(c)}">`).join("");
    $("#add-btn").hidden = !data.github;
    mergePending();
    render();
    scheduleRefresh();
  }

  // ------------------------------------------------------------ aggiornamento automatico
  // Controlla se è stato pubblicato un file dati più recente e lo ricarica senza F5.
  // Con BL in coda controlla ogni 30 s, altrimenti ogni 5 minuti.
  function scheduleRefresh() {
    clearTimeout(refresh.timer);
    const queued = state.data.shipments.some((s) => s.status === "QUEUED");
    refresh.timer = setTimeout(refresh, queued ? 30_000 : 300_000);
  }

  async function refresh() {
    if (!state.data || !state.key) return;
    try {
      const r = await fetch(`data/shipments.enc.js?t=${Date.now()}`, { cache: "no-store" });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const text = await r.text();
      const payload = JSON.parse(text.slice(text.indexOf("{"), text.lastIndexOf("}") + 1));
      if (payload.ct === window.ZT_ENCRYPTED.ct) return;
      if (payload.salt !== window.ZT_ENCRYPTED.salt) { location.reload(); return; }  // password cambiata
      const data = await decrypt(state.key, payload);
      if (data.generated_at <= state.data.generated_at) return;

      const queuedBefore = state.data.shipments.filter((s) => s.status === "QUEUED").map((s) => s.bl);
      const openBl = state.selected?.bl;
      window.ZT_ENCRYPTED = payload;
      start(data);
      const arrived = queuedBefore.filter((bl) => data.shipments.some((s) => s.bl === bl));
      toast(arrived.length ? `Dati aggiornati: ${arrived.join(", ")} tracciato.` : "Dati aggiornati.");
      if (openBl && state.selected?.bl === openBl) openDrawer(openBl);
    } catch {
      // rete assente o file in pubblicazione: si riprova al prossimo giro
    } finally {
      if (state.data) scheduleRefresh();
    }
  }

  // ------------------------------------------------------------ BL in coda (aggiunti dal portale, non ancora tracciati)
  function readPending() {
    try { return JSON.parse(localStorage.getItem(PENDING_STORE) || "[]"); } catch { return []; }
  }
  function writePending(list) {
    try { localStorage.setItem(PENDING_STORE, JSON.stringify(list)); } catch { /* storage non disponibile */ }
  }
  function queuedShipment(e) {
    return { ...e, status: "QUEUED", containers: [], containers_count: 0, returned_count: 0, delivered_count: 0 };
  }
  function mergePending() {
    const known = new Set(state.data.shipments.filter((s) => !s.archived).map((s) => s.bl));
    const still = readPending().filter((e) => !known.has(e.bl));
    writePending(still);
    const stillBl = new Set(still.map((e) => e.bl));
    state.data.shipments = state.data.shipments.filter((s) => !stillBl.has(s.bl));
    still.forEach((e) => state.data.shipments.unshift(queuedShipment(e)));
  }

  // ------------------------------------------------------------ GitHub (repo privato: data/bl_list.json)
  const utf8ToB64 = (str) => {
    const bytes = new TextEncoder().encode(str);
    let bin = "";
    for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    return btoa(bin);
  };
  const b64ToUtf8 = (b) => new TextDecoder().decode(b64(b.replace(/\s/g, "")));

  async function ghRequest(method, body) {
    const g = state.data.github;
    const url = `https://api.github.com/repos/${g.owner}/${g.repo}/contents/${g.path}` + (method === "GET" ? `?ref=${g.branch}` : "");
    const r = await fetch(url, {
      method,
      cache: "no-store",
      headers: { Authorization: `Bearer ${g.token}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28" },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!r.ok) {
      const err = new Error(r.status === 401 || r.status === 403 ? "Autorizzazione GitHub non valida o scaduta." : `GitHub HTTP ${r.status}`);
      err.status = r.status;
      throw err;
    }
    return r.json();
  }

  // Legge bl_list.json, applica la modifica e salva; ritenta se il file è cambiato nel frattempo.
  async function updateBlList(mutate, message) {
    for (let attempt = 0; attempt < 3; attempt++) {
      const file = await ghRequest("GET");
      const list = JSON.parse(b64ToUtf8(file.content));
      const result = mutate(list);
      try {
        await ghRequest("PUT", {
          message,
          branch: state.data.github.branch,
          sha: file.sha,
          content: utf8ToB64(JSON.stringify(list, null, 2) + "\n"),
        });
        return result;
      } catch (e) {
        if (e.status !== 409 && e.status !== 422) throw e;
      }
    }
    throw new Error("Salvataggio non riuscito, riprovare.");
  }

  function carrierFromBl(bl) {
    if (/^(MEDU|MSCU)/.test(bl)) return "MSC";
    if (/^(MAEU)?\d{9}$/.test(bl)) return "MAERSK";
    return "";
  }

  function toast(text) {
    const t = $("#toast");
    t.textContent = text;
    t.hidden = false;
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => { t.hidden = true; }, 4500);
  }

  function filtered() {
    const q = state.q.trim().toLowerCase();
    return state.data.shipments.filter((s) => {
      if (s.archived) return false;
      if (state.carrier && s.carrier !== state.carrier) return false;
      if (state.customer && s.customer !== state.customer) return false;
      if (state.status === "OPEN" && !isOpen(s)) return false;
      if (state.status === "LATE" && !isLate(s)) return false;
      if (state.status === "ARRIVED_ALL" && !["ARRIVED", "DELIVERED"].includes(s.status)) return false;
      if (state.status === "IN_TRANSIT" && !["PENDING", "IN_TRANSIT"].includes(s.status)) return false;
      if (["RETURNED", "NO_DATA"].includes(state.status) && s.status !== state.status) return false;
      if (state.dateFrom || state.dateTo) {
        const d = dateValue(s, state.dateField);
        if (!d) return false;
        if (state.dateFrom && d < state.dateFrom) return false;
        if (state.dateTo && d > state.dateTo) return false;
      }
      if (!q) return true;
      const hay = [s.bl, s.customer, s.carrier, s.pol, s.pod, s.vessel, ...(s.orders || []), ...(s.transshipments || []),
        ...(s.containers || []).map((c) => c.number)].join(" ").toLowerCase();
      return hay.includes(q);
    });
  }

  function dateValue(s, field) {
    const v = field === "arrival_or_eta" ? s.arrival || s.eta : s[field];
    return v ? v.slice(0, 10) : "";
  }

  function sortValue(s, key) {
    if (key === "status") return STATUS_RANK.indexOf(s.status);
    if (key === "arrival_or_eta") return dateValue(s, key);
    const v = s[key];
    if (NUMERIC_SORT.has(key)) return v ?? -Infinity;
    return v ?? "";
  }

  function render() {
    renderKpis();
    const list = filtered().sort((a, b) => {
      const qa = a.status === "QUEUED", qb = b.status === "QUEUED";
      if (qa !== qb) return qa ? -1 : 1;  // BL appena aggiunti sempre in cima
      const va = sortValue(a, state.sort), vb = sortValue(b, state.sort);
      const cmp = typeof va === "number" && typeof vb === "number" ? va - vb : String(va).localeCompare(String(vb));
      return state.dir === "asc" ? cmp : -cmp;
    });

    document.querySelectorAll("#table th").forEach((th) => {
      th.dataset.dir = th.dataset.sort === state.sort ? state.dir : "";
    });

    // la selezione vale solo per BL ancora visibili nel portale
    const alive = new Set(state.data.shipments.filter((s) => !s.archived).map((s) => s.bl));
    state.checked.forEach((bl) => { if (!alive.has(bl)) state.checked.delete(bl); });

    $("#rows").innerHTML = list.map(rowHtml).join("");
    $("#empty").hidden = list.length > 0;
    const total = alive.size;
    const containers = list.reduce((n, s) => n + (s.containers_count || 0), 0);
    $("#count").textContent = (list.length === total ? `${total} spedizioni` : `${list.length} di ${total} spedizioni`)
      + ` · ${containers} container`;
    renderSelection(list);
  }

  function renderSelection(list) {
    const canArchive = !!state.data.github;
    $("#table").classList.toggle("no-select", !canArchive);
    const all = $("#sel-all");
    const visibleChecked = list.filter((s) => state.checked.has(s.bl)).length;
    all.checked = list.length > 0 && visibleChecked === list.length;
    all.indeterminate = visibleChecked > 0 && visibleChecked < list.length;
    const n = state.checked.size;
    $("#selection-bar").hidden = !canArchive || n === 0;
    $("#sel-count").textContent = `${n} ${n === 1 ? "BL selezionato" : "BL selezionati"}`;
  }

  function renderKpis() {
    const all = state.data.shipments.filter((s) => !s.archived);
    const open = all.filter(isOpen);
    const transit = all.filter((s) => ["PENDING", "IN_TRANSIT"].includes(s.status));
    const arrived = all.filter((s) => ["ARRIVED", "DELIVERED"].includes(s.status));
    const returned = all.filter((s) => s.status === "RETURNED");
    const late = all.filter(isLate);
    const sumC = (arr, fn) => arr.reduce((n, s) => n + fn(s), 0);
    const contTransit = sumC(transit, (s) => s.containers_count || 0);
    const toReturn = sumC(arrived, (s) => (s.containers_count || 0) - (s.returned_count || 0));
    const nextEta = transit.map((s) => s.eta).filter(Boolean).sort()[0];

    const cards = [
      { f: "OPEN", cls: "", label: "Spedizioni aperte", value: open.length, sub: `${sumC(open, (s) => s.containers_count || 0)} container` },
      { f: "IN_TRANSIT", cls: "st-IN_TRANSIT", label: "In viaggio", value: transit.length, sub: `${contTransit} container${nextEta ? ` · prossimo arrivo ${fmtDate(nextEta)}` : ""}` },
      { f: "ARRIVED_ALL", cls: "st-ARRIVED", label: "Arrivati", value: arrived.length, sub: `${toReturn} container da rientrare` },
      { f: "RETURNED", cls: "st-RETURNED", label: "Rientrati vuoti", value: returned.length, sub: `${sumC(returned, (s) => s.containers_count || 0)} container chiusi` },
      { f: "LATE", cls: "st-NO_DATA", label: "In ritardo", value: late.length, sub: `oltre ${LATE_DAYS} gg sull'ETA prevista` },
    ];
    $("#kpis").innerHTML = cards.map((c) => `
      <button type="button" class="kpi ${c.cls} ${state.status === c.f ? "active" : ""}" data-filter="${c.f}">
        <span class="kpi-label">${esc(c.label)}</span>
        <span class="kpi-value">${c.value}</span>
        <span class="kpi-sub">${esc(c.sub)}</span>
      </button>`).join("");
  }

  function rowHtml(s, i) {
    const n = s.containers_count || 0;
    const arrival = s.arrival
      ? `<div class="cell-main">${fmtDate(s.arrival)}</div><div class="cell-sub">${esc(port(s.pod))}</div>`
      : s.eta
        ? `<div class="cell-main est">ETA ${fmtDate(s.eta)}</div><div class="cell-sub">${esc(port(s.pod))}</div>`
        : '<span class="muted">—</span>';
    const ret = n
      ? `<div class="cell-main">${s.returned_count}/${n}${s.last_return ? ` · ${fmtDate(s.last_return)}` : ""}</div>
         <div class="progress">${Array.from({ length: n }, (_, i) => `<i class="${i < s.returned_count ? "on" : ""}"></i>`).join("")}</div>`
      : '<span class="muted">—</span>';
    return `
      <tr data-bl="${esc(s.bl)}" tabindex="0" class="${state.checked.has(s.bl) ? "selected" : ""}">
        <td class="col-check sel-col"><input type="checkbox" data-check aria-label="Seleziona ${esc(s.bl)}" ${state.checked.has(s.bl) ? "checked" : ""}></td>
        <td class="col-n num">${i + 1}</td>
        <td data-label="Stato">${badge(s.status)}</td>
        <td data-label="BL"><div class="cell-main mono">${esc(s.bl)}</div><div class="cell-sub"><span class="carrier">${esc(s.carrier)}</span> ${esc((s.orders || []).join(", "))}</div></td>
        <td data-label="Cliente" class="wide"><div class="cell-main">${esc(title(s.customer))}</div>${s.tons ? `<div class="cell-sub">${s.tons.toLocaleString("it-IT")} t</div>` : ""}</td>
        <td data-label="Tratta" class="wide"><div class="cell-main">${esc(port(s.pol))} → ${esc(port(s.pod))}</div><div class="cell-sub">${esc(s.vessel ? title(s.vessel) : "")}</div></td>
        <td data-label="Container" class="num">${n || "—"}</td>
        <td data-label="Partenza"><div class="cell-main">${fmtDate(s.departure)}</div><div class="cell-sub">spedito ${fmtDate(s.ship_date)}</div></td>
        <td data-label="Arrivo / ETA">${arrival}</td>
        <td data-label="Rientro vuoto">${ret}</td>
        <td data-label="Ritardo" class="num">${delayHtml(s.delay_days)}</td>
      </tr>`;
  }

  // ------------------------------------------------------------ drawer
  function openDrawer(bl) {
    const s = state.data.shipments.find((x) => x.bl === bl);
    if (!s) return;
    state.selected = s;
    state.container = 0;
    renderDrawer();
    $("#drawer-backdrop").hidden = false;
    const d = $("#drawer");
    d.setAttribute("aria-hidden", "false");
    requestAnimationFrame(() => d.classList.add("open"));
    d.focus();
  }

  function closeDrawer() {
    const d = $("#drawer");
    d.classList.remove("open");
    d.setAttribute("aria-hidden", "true");
    $("#drawer-backdrop").hidden = true;
    state.selected = null;
  }

  function stepsHtml(s) {
    const n = s.containers_count || 0;
    const delivered = s.delivered_count || 0;
    const returned = s.returned_count || 0;
    const steps = [
      { label: "Partenza", date: s.departure, sub: port(s.pol), done: !!s.departure },
      { label: "Arrivo", date: s.arrival || s.eta, sub: s.arrival ? port(s.pod) : s.eta ? "stimato" : port(s.pod), done: !!s.arrival, est: !s.arrival && s.eta },
      { label: "Ritiro cliente", date: null, sub: n ? `${delivered}/${n} container` : "", done: n && delivered === n, partial: delivered > 0 && delivered < n },
      { label: "Rientro vuoto", date: s.last_return, sub: n ? `${returned}/${n} container` : "", done: n && returned === n, partial: returned > 0 && returned < n },
    ];
    const nextIdx = steps.findIndex((x) => !x.done);
    return `<div class="steps">${steps.map((x, i) => `
      <div class="step ${x.done ? "done" : x.partial ? "partial" : i === nextIdx ? "next" : ""}">
        <div class="step-label">${esc(x.label)}</div>
        <div class="step-date ${x.est ? "est" : ""}">${x.date ? fmtDate(x.date) : x.done ? "✓" : "—"}</div>
        <div class="step-sub">${esc(x.sub)}</div>
      </div>`).join("")}</div>`;
  }

  function renderDrawer() {
    const s = state.selected;
    const cs = s.containers || [];
    const c = cs[state.container];
    const info = [
      ["Cliente", title(s.customer)],
      ["Armatore", s.carrier],
      ["Ordini", (s.orders || []).join(", ") || "—"],
      ["Quantità", s.tons ? `${s.tons.toLocaleString("it-IT")} t · ${(s.delivery_notes || []).length} buoni` : "—"],
      ["Data spedizione", fmtDate(s.ship_date)],
      ["ETA prevista (ordine)", fmtDate(s.eta_planned)],
      [s.arrival ? "Arrivo effettivo" : "ETA armatore", fmtDate(s.arrival || s.eta)],
      ["Ritardo", null, delayHtml(s.delay_days)],
      ["Transit time", s.transit_days != null ? `${s.transit_days} giorni` : "—"],
      ["Nave attuale / ultima", s.vessel ? title(s.vessel) : "—"],
      ["Ultimo controllo", fmtDateTime(s.last_check)],
    ];

    $("#drawer").innerHTML = `
      <div class="d-head">
        <div>
          <h2 class="mono">${esc(s.bl)}</h2>
          <div>${badge(s.status)} <span class="carrier">${esc(s.carrier)}</span></div>
        </div>
        <button type="button" class="btn btn-ghost" data-close>Chiudi ✕</button>
      </div>
      <div class="d-body">
        ${s.error ? `<div class="alert">Ultimo aggiornamento non riuscito: ${esc(s.error)}</div>` : ""}
        <section class="card">${stepsHtml(s)}</section>

        <section class="card">
          <h3>Tratta</h3>
          <div class="route">
            <span>${esc(place(s.pol))}</span>
            ${(s.transshipments || []).map((t) => `<span class="arrow">→</span><span class="ts">${esc(place(t))}</span>`).join("")}
            <span class="arrow">→</span><span>${esc(place(s.pod))}</span>
          </div>
        </section>

        <section class="card">
          <h3>Dettagli</h3>
          <dl class="grid-info">${info.map(([k, v, html]) => `<div><dt>${esc(k)}</dt><dd>${html ?? esc(v)}</dd></div>`).join("")}</dl>
        </section>

        <section class="card">
          <h3>Container (${cs.length})</h3>
          ${cs.length ? `<div class="scroll-x"><table class="ctable">
            <thead><tr><th>Container</th><th>Tipo</th><th>Partenza</th><th>Arrivo</th><th>Ritiro</th><th>Rientro vuoto</th><th class="num">Gg fuori</th></tr></thead>
            <tbody>${cs.map((x, i) => `
              <tr data-container="${i}" class="${i === state.container ? "sel" : ""}">
                <td class="mono">${esc(x.number)}</td>
                <td>${esc(title(x.type))}</td>
                <td>${fmtDate(x.departure)}</td>
                <td>${x.arrival ? fmtDate(x.arrival) : x.next?.code === "ETA" ? `<span class="est">${fmtDate(x.pod_eta || x.next.date)}</span>` : "—"}</td>
                <td>${fmtDate(x.delivery)}</td>
                <td>${x.empty_return ? `<span class="badge st-RETURNED">${fmtDate(x.empty_return)}</span>` : "—"}</td>
                <td class="num">${x.days_to_return != null ? `${x.days_to_return}` : x.days_out != null ? `<strong>${x.days_out}</strong> <span class="muted">in corso</span>` : "—"}</td>
              </tr>`).join("")}</tbody></table></div>` : '<p class="muted">Nessun container disponibile.</p>'}
        </section>

        ${c ? `<section class="card">
          <h3>Eventi · <span class="mono">${esc(c.number)}</span></h3>
          <ol class="timeline">${c.events.map((e) => `
            <li class="${e.actual ? "" : "future"} ${KEY_EVENTS.has(e.code) ? "key" : ""}">
              <div class="tl-date">${fmtDate(e.date)}${e.time ? `<small>${esc(e.time)}</small>` : ""}</div>
              <div class="tl-dot"></div>
              <div class="tl-text">
                <strong>${esc(e.label)}${e.actual ? "" : " (previsto)"}</strong>
                <span>${esc(place(e.location))}${e.vessel ? ` · ${esc(title(e.vessel))}${e.voyage ? ` ${esc(e.voyage)}` : ""}` : ""}</span>
              </div>
            </li>`).join("")}</ol>
        </section>` : ""}

        ${s.status === "QUEUED" ? `<section class="card"><p class="muted" style="margin:0">BL aggiunto dal portale il ${fmtDate(s.added_at)}: i dati compariranno qui da soli entro pochi minuti (di solito 5–10, con il PC di tracking acceso).</p></section>` : ""}

        <section class="links">
          <a href="${trackingUrl(s)}" target="_blank" rel="noopener">Apri sul sito ${esc(title(s.carrier))} ↗</a>
          ${state.data.github ? `<button type="button" class="btn btn-danger" data-archive style="margin-left:auto">Archivia BL</button>` : ""}
        </section>
      </div>`;
  }

  // ------------------------------------------------------------ export
  function exportCsv() {
    const cols = [
      ["BL", (s) => s.bl], ["Armatore", (s) => s.carrier], ["Cliente", (s) => s.customer], ["Ordini", (s) => (s.orders || []).join(" ")],
      ["Stato", (s) => STATUS[s.status]?.label || s.status], ["POL", (s) => s.pol], ["POD", (s) => s.pod],
      ["Container", (s) => s.containers_count], ["Data spedizione", (s) => fmtDate(s.ship_date)], ["Partenza", (s) => fmtDate(s.departure)],
      ["ETA prevista", (s) => fmtDate(s.eta_planned)], ["ETA armatore", (s) => fmtDate(s.eta)], ["Arrivo", (s) => fmtDate(s.arrival)],
      ["Arrivo Nave a Destino", (s) => (s.arrival ? "Sì" : "No")], ["Rientrati", (s) => `${s.returned_count ?? 0}/${s.containers_count ?? 0}`],
      ["Rientrato", (s) => (s.status === "RETURNED" ? "Sì" : "No")], ["Ultimo rientro", (s) => fmtDate(s.last_return)],
      ["Ritardo gg", (s) => s.delay_days ?? ""], ["Container n.", (s) => (s.containers || []).map((c) => c.number).join(" ")],
    ];
    const q = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const lines = [cols.map((c) => q(c[0])).join(";"), ...filtered().map((s) => cols.map((c) => q(c[1](s))).join(";"))];
    const blob = new Blob(["﻿" + lines.join("\r\n")], { type: "text/csv;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `zoffoli-tracker-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  // ------------------------------------------------------------ events
  $("#search").addEventListener("input", (e) => { state.q = e.target.value; render(); });
  $("#f-carrier").addEventListener("change", (e) => { state.carrier = e.target.value; render(); });
  $("#f-customer").addEventListener("change", (e) => { state.customer = e.target.value; render(); });
  $("#f-status").addEventListener("change", (e) => { state.status = e.target.value; render(); });
  $("#f-date-field").addEventListener("change", (e) => { state.dateField = e.target.value; render(); });
  $("#f-date-from").addEventListener("change", (e) => { state.dateFrom = e.target.value; render(); });
  $("#f-date-to").addEventListener("change", (e) => { state.dateTo = e.target.value; render(); });
  $("#f-reset").addEventListener("click", () => {
    Object.assign(state, { q: "", carrier: "", customer: "", status: "", dateField: "ship_date", dateFrom: "", dateTo: "" });
    $("#search").value = "";
    ["#f-carrier", "#f-customer", "#f-status", "#f-date-from", "#f-date-to"].forEach((sel) => { $(sel).value = ""; });
    $("#f-date-field").value = "ship_date";
    render();
  });
  $("#export-btn").addEventListener("click", exportCsv);

  // Selezione multipla
  $("#sel-all").addEventListener("change", (e) => {
    filtered().forEach((s) => (e.target.checked ? state.checked.add(s.bl) : state.checked.delete(s.bl)));
    render();
  });
  $("#sel-clear").addEventListener("click", () => { state.checked.clear(); render(); });
  $("#sel-archive").addEventListener("click", (e) => archiveBls([...state.checked], e.currentTarget));

  $("#kpis").addEventListener("click", (e) => {
    const k = e.target.closest("[data-filter]");
    if (!k) return;
    state.status = state.status === k.dataset.filter ? "" : k.dataset.filter;
    $("#f-status").value = [...$("#f-status").options].some((o) => o.value === state.status) ? state.status : "";
    render();
  });

  $("#table thead").addEventListener("click", (e) => {
    const th = e.target.closest("th[data-sort]");
    if (!th) return;
    if (state.sort === th.dataset.sort) state.dir = state.dir === "asc" ? "desc" : "asc";
    else { state.sort = th.dataset.sort; state.dir = "asc"; }
    render();
  });

  $("#rows").addEventListener("click", (e) => {
    const tr = e.target.closest("tr[data-bl]");
    if (!tr) return;
    if (e.target.closest(".col-check")) {
      const box = tr.querySelector("[data-check]");
      if (e.target !== box) box.checked = !box.checked;  // clic sulla cella, non sulla casella
      box.checked ? state.checked.add(tr.dataset.bl) : state.checked.delete(tr.dataset.bl);
      render();
      return;
    }
    openDrawer(tr.dataset.bl);
  });
  $("#rows").addEventListener("keydown", (e) => {
    const tr = e.target.closest("tr[data-bl]");
    if (e.target.matches("input")) return;  // spazio sulla casella = seleziona, non apre il dettaglio
    if (tr && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); openDrawer(tr.dataset.bl); }
  });

  // Aggiungi BL
  const addDialog = $("#add-dialog");
  $("#add-btn").addEventListener("click", () => {
    $("#add-form").reset();
    $("#add-error").hidden = true;
    addDialog.showModal();
    $("#add-bl").focus();
  });
  addDialog.querySelector("[data-cancel]").addEventListener("click", () => addDialog.close());
  $("#add-bl").addEventListener("input", (e) => {
    const bl = e.target.value.toUpperCase().replace(/\s/g, "");
    const c = carrierFromBl(bl);
    if (c) $("#add-carrier").value = c;
  });

  $("#add-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const err = $("#add-error");
    const btn = $("#add-submit");
    const bl = $("#add-bl").value.toUpperCase().replace(/\s/g, "");
    const carrier = $("#add-carrier").value;
    err.hidden = true;

    const fail = (msg) => { err.textContent = msg; err.hidden = false; };
    if (!/^[A-Z0-9]{8,20}$/.test(bl)) return fail("Numero BL non valido (solo lettere e numeri).");
    if (!carrier) return fail("Seleziona l'armatore.");
    if (carrier === "MAERSK" && !/^(MAEU)?\d{9}$/.test(bl)) return fail("Per Maersk il BL è di 9 cifre (con o senza prefisso MAEU).");
    const normBl = carrier === "MAERSK" && /^\d{9}$/.test(bl) ? `MAEU${bl}` : bl;
    if (state.data.shipments.some((s) => s.bl === normBl && !s.archived)) return fail("Questo BL è già presente.");

    const order = $("#add-order").value.trim();
    const entry = {
      bl: normBl, carrier, customer: $("#add-customer").value.trim() || null,
      orders: order ? [order] : [], ship_date: null, eta_planned: null, tons: null,
      delivery_notes: [], note: $("#add-note").value.trim(), source: "portale",
      added_at: new Date().toISOString().slice(0, 10), archived: false,
    };

    btn.disabled = true;
    btn.textContent = "Salvataggio…";
    try {
      const added = await updateBlList((list) => {
        const existing = list.find((x) => x.bl === normBl);
        if (existing && !existing.archived) return false;
        if (existing) Object.assign(existing, { archived: false });
        else list.unshift(entry);
        return true;
      }, `Portale: aggiunto BL ${normBl}`);
      if (!added) return fail("Questo BL è già presente.");
      writePending([...readPending().filter((x) => x.bl !== normBl), entry]);
      state.data.shipments = state.data.shipments.filter((s) => s.bl !== normBl);  // eventuale copia archiviata
      state.data.shipments.unshift(queuedShipment(entry));
      addDialog.close();
      render();
      scheduleRefresh();
      toast(`BL ${normBl} aggiunto: i dati compariranno qui entro pochi minuti.`);
    } catch (ex) {
      fail(ex.message || "Errore di rete, riprovare.");
    } finally {
      btn.disabled = false;
      btn.textContent = "Aggiungi";
    }
  });

  // Archivia uno o più BL con un solo salvataggio su GitHub
  async function archiveBls(bls, button) {
    if (!bls.length) return;
    const what = bls.length === 1 ? `il BL ${bls[0]}` : `${bls.length} BL:\n${bls.slice(0, 15).join(", ")}${bls.length > 15 ? "…" : ""}`;
    if (!confirm(`Archiviare ${what}?\n\nNon compariranno più nel portale e non verranno più tracciati.`)) return;
    const label = button.textContent;
    button.disabled = true;
    button.textContent = "Archiviazione…";
    try {
      const set = new Set(bls);
      await updateBlList((list) => {
        list.forEach((x) => { if (set.has(x.bl)) x.archived = true; });
      }, bls.length === 1 ? `Portale: archiviato BL ${bls[0]}` : `Portale: archiviati ${bls.length} BL (${bls.join(", ")})`);
      writePending(readPending().filter((x) => !set.has(x.bl)));
      state.data.shipments.forEach((s) => { if (set.has(s.bl)) s.archived = true; });
      bls.forEach((bl) => state.checked.delete(bl));
      if (state.selected && set.has(state.selected.bl)) closeDrawer();
      render();
      toast(bls.length === 1 ? `BL ${bls[0]} archiviato.` : `${bls.length} BL archiviati.`);
    } catch (ex) {
      alert(ex.message || "Errore di rete, riprovare.");
    } finally {
      button.disabled = false;
      button.textContent = label;
    }
  }

  $("#drawer").addEventListener("click", (e) => {
    if (e.target.closest("[data-close]")) return closeDrawer();
    const arch = e.target.closest("[data-archive]");
    if (arch) return archiveBls([state.selected.bl], arch);
    const tr = e.target.closest("tr[data-container]");
    if (tr) { state.container = Number(tr.dataset.container); renderDrawer(); }
  });
  $("#drawer-backdrop").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && state.selected) closeDrawer(); });

  init();
})();
