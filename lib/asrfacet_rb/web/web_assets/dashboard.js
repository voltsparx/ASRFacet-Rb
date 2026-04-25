const defaults = __DEFAULT_CONFIG_JSON__;
const state = {
  sessions: [],
  current: null,
  currentSession: null,
  dirty: false,
  autosaveTimer: null,
  refreshInFlight: false,
  docs: [],
  about: "",
  firstRun: false,
  firstRunGuide: [],
  activeDoc: null,
  activeView: "workbench",
  activeFormTab: "target",
  sessionQuery: "",
  sessionFilter: "all",
  docsQuery: "",
  bootstrap: {}
};

const fields = [
  "name",
  "target",
  "mode",
  "format",
  "ports",
  "threads",
  "timeout",
  "delay",
  "scope",
  "exclude",
  "webhook-url",
  "webhook-platform",
  "shodan-key",
  "monitor",
  "memory",
  "headless",
  "verbose",
  "adaptive-rate"
];

const el = (id) => document.getElementById(id);

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#39;"
  }[char] || char));
}

function parseJson(response) {
  return response.json().catch(() => ({}));
}

function statusClass(status) {
  return `status-pill ${String(status || "idle").toLowerCase()}`;
}

function severityClass(value) {
  return String(value || "info").toLowerCase();
}

function relativeTime(value) {
  if (!value) return "never";
  const timestamp = new Date(value).getTime();
  if (Number.isNaN(timestamp)) return "unknown";
  const diff = Math.max(0, Date.now() - timestamp);
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

async function api(url, options = {}) {
  const response = await fetch(url, Object.assign({ headers: { "Content-Type": "application/json" } }, options));
  const payload = await parseJson(response);
  payload.ok = response.ok;
  payload.status = response.status;
  return payload;
}

function modeLabel(mode) {
  return {
    scan: "Full scan",
    passive: "Passive",
    dns: "DNS only",
    ports: "Ports only"
  }[String(mode || "scan")] || String(mode || "scan");
}

function quoteShell(value) {
  if (!value) return "";
  return /\s/.test(value) ? `"${String(value).replace(/"/g, '\\"')}"` : String(value);
}

function setSidebarOpen(open) {
  document.body.classList.toggle("sidebar-open", open);
  el("sidebar-backdrop").classList.toggle("hidden", !open);
}

function setDrawerOpen(open) {
  el("activity-drawer").classList.toggle("open", open);
  el("drawer-backdrop").classList.toggle("hidden", !open);
}

function switchView(view) {
  state.activeView = view;
  document.querySelectorAll("[data-view]").forEach((node) => {
    node.classList.toggle("active", node.getAttribute("data-view") === view);
  });
  document.querySelectorAll("[data-view-panel]").forEach((node) => {
    node.classList.toggle("active", node.getAttribute("data-view-panel") === view);
  });
  setSidebarOpen(false);
}

function switchFormTab(tab) {
  state.activeFormTab = tab;
  document.querySelectorAll("[data-form-tab]").forEach((node) => {
    node.classList.toggle("active", node.getAttribute("data-form-tab") === tab);
  });
  document.querySelectorAll("[data-form-panel]").forEach((node) => {
    node.classList.toggle("active", node.getAttribute("data-form-panel") === tab);
  });
}

function formData() {
  return {
    id: state.current,
    name: el("name").value.trim(),
    config: {
      target: el("target").value.trim(),
      mode: el("mode").value,
      format: el("format").value,
      ports: el("ports").value.trim(),
      threads: Number(el("threads").value || 50),
      timeout: Number(el("timeout").value || 10),
      delay: Number(el("delay").value || 0),
      scope: el("scope").value.trim(),
      exclude: el("exclude").value.trim(),
      webhook_url: el("webhook-url").value.trim(),
      webhook_platform: el("webhook-platform").value,
      shodan_key: el("shodan-key").value.trim(),
      monitor: el("monitor").checked,
      memory: el("memory").checked,
      headless: el("headless").checked,
      verbose: el("verbose").checked,
      adaptive_rate: el("adaptive-rate").checked
    }
  };
}

function currentDraft() {
  return state.currentSession || { name: "Untitled session", config: defaults };
}

function fillForm(session) {
  const config = Object.assign({}, defaults, session?.config || {});
  el("name").value = session?.name || "Untitled session";
  el("target").value = config.target || "";
  el("mode").value = config.mode || "scan";
  el("format").value = config.format || "html";
  el("ports").value = config.ports || "top100";
  el("threads").value = config.threads || 50;
  el("timeout").value = config.timeout || 10;
  el("delay").value = config.delay || 0;
  el("scope").value = config.scope || "";
  el("exclude").value = config.exclude || "";
  el("webhook-url").value = config.webhook_url || "";
  el("webhook-platform").value = config.webhook_platform || "slack";
  el("shodan-key").value = config.shodan_key || "";
  el("monitor").checked = config.monitor !== false;
  el("memory").checked = config.memory !== false;
  el("headless").checked = config.headless === true;
  el("verbose").checked = config.verbose !== false;
  el("adaptive-rate").checked = config.adaptive_rate !== false;
  state.dirty = false;
  renderBuilderNotes(formData());
  renderCommandPreview(formData());
  syncChrome(session || currentDraft());
}

function buildCommandPreview(payload) {
  const config = payload?.config || defaults;
  const target = quoteShell(config.target || "TARGET");
  const parts = ["asrfacet-rb"];

  switch (config.mode) {
    case "passive":
      parts.push("passive", target);
      break;
    case "dns":
      parts.push("dns", target);
      break;
    case "ports":
      parts.push("ports", target);
      break;
    default:
      parts.push("scan", target);
      break;
  }

  if (config.format && config.format !== "html") parts.push("--format", config.format);
  if (config.ports && config.ports !== "top100" && config.mode !== "dns" && config.mode !== "passive") parts.push("--ports", quoteShell(config.ports));
  if (Number(config.threads || 50) !== 50 && config.mode !== "dns") parts.push("--threads", String(config.threads));
  if (Number(config.timeout || 10) !== 10 && config.mode !== "passive") parts.push("--timeout", String(config.timeout));
  if (Number(config.delay || 0) > 0) parts.push("--delay", String(config.delay));
  if (config.scope) parts.push("--scope", quoteShell(config.scope));
  if (config.exclude) parts.push("--exclude", quoteShell(config.exclude));
  if (config.monitor) parts.push("--monitor");
  if (config.memory) parts.push("--memory");
  if (config.headless && config.mode === "scan") parts.push("--headless");
  if (config.verbose) parts.push("--verbose");
  if (config.adaptive_rate) parts.push("--adaptive-rate");
  if (config.webhook_url) {
    parts.push("--webhook-url", quoteShell(config.webhook_url));
    parts.push("--webhook-platform", config.webhook_platform || "slack");
  }
  if (config.shodan_key) parts.push("--shodan-key", quoteShell(config.shodan_key));

  return parts.join(" ");
}

function renderCommandPreview(payload) {
  el("command-preview").textContent = buildCommandPreview(payload);
}

function renderBuilderNotes(payload) {
  const config = payload?.config || defaults;
  const notes = [
    {
      title: "Target posture",
      copy: config.target ? `Current target is ${config.target}. ${config.scope ? "An explicit allowlist is active." : "No additional allowlist is configured yet."}` : "No target is selected yet. Add a hostname or IP before saving or running."
    },
    {
      title: "Execution pressure",
      copy: `${modeLabel(config.mode)} mode with ${config.threads || 50} threads and ${config.timeout || 10}s timeout. ${Number(config.delay || 0) > 0 ? `Base delay is ${config.delay}ms.` : "No base delay is configured."}`
    },
    {
      title: "Operator aids",
      copy: `${config.monitor ? "Monitoring is on" : "Monitoring is off"}, ${config.memory ? "recon memory is on" : "recon memory is off"}, and ${config.headless ? "headless rendering is enabled." : "headless rendering is disabled."}`
    }
  ];

  el("builder-notes").innerHTML = notes.map((note) => `
    <div class="builder-note">
      <span>${escapeHtml(note.title)}</span>
      <strong>${escapeHtml(note.copy)}</strong>
    </div>
  `).join("");
}

function renderSessionList() {
  const container = el("session-list");
  const query = state.sessionQuery.trim().toLowerCase();
  const filteredSessions = state.sessions.filter((session) => {
    const matchesQuery = !query || [session.name, session.target, session.mode, session.status].some((value) => String(value || "").toLowerCase().includes(query));
    if (!matchesQuery) return false;

    switch (state.sessionFilter) {
      case "running":
        return session.running === true || String(session.status || "").toLowerCase() === "running";
      case "attention":
        return ["failed", "interrupted", "warning", "error"].includes(String(session.status || "").toLowerCase()) || Boolean(session.error) || (Array.isArray(session.integrity?.issues) && session.integrity.issues.length > 0);
      default:
        return true;
    }
  });

  el("meta-sessions").textContent = filteredSessions.length === state.sessions.length ? `${filteredSessions.length} session${filteredSessions.length === 1 ? "" : "s"}` : `${filteredSessions.length} of ${state.sessions.length} sessions`;
  container.innerHTML = filteredSessions.map((session) => `
    <button class="session-card ${session.id === state.current ? "active" : ""}" data-session-id="${escapeHtml(session.id || "")}" type="button">
      <div class="session-card-head">
        <strong>${escapeHtml(session.name || "Untitled session")}</strong>
        <span class="${statusClass(session.status)}">${escapeHtml(session.status || "idle")}</span>
      </div>
      <div class="session-meta">
        <div><span class="nav-title">Target</span><div>${escapeHtml(session.target || "No target yet")}</div></div>
        <div><span class="nav-title">Mode</span><div>${escapeHtml(modeLabel(session.mode || "scan"))}</div></div>
      </div>
      <div class="nav-hint">Updated ${escapeHtml(relativeTime(session.updated_at))}</div>
    </button>
  `).join("") || `<div class="notice">${state.sessions.length > 0 ? "No sessions match the current search or filter." : "No saved sessions yet. Create one to begin building a recon workflow."}</div>`;

  Array.from(container.querySelectorAll("[data-session-id]")).forEach((node) => {
    node.addEventListener("click", () => loadSession(node.getAttribute("data-session-id")));
  });
}

function renderBarChart(summary) {
  const rows = [
    ["Hosts", summary.subdomains || 0],
    ["IPs", summary.ips || 0],
    ["Ports", summary.open_ports || 0],
    ["Web", summary.http_responses || 0],
    ["Findings", summary.findings || 0]
  ];
  const max = Math.max(1, ...rows.map(([, value]) => Number(value || 0)));
  el("bar-chart").innerHTML = rows.map(([label, value]) => `
    <div class="bar-unit">
      <div class="bar-unit-meter" style="height:${Math.max(18, Math.round((Number(value || 0) / max) * 160))}px"></div>
      <strong>${escapeHtml(String(value || 0))}</strong>
      <div class="bar-unit-label">${escapeHtml(label)}</div>
    </div>
  `).join("");
}

function renderSnapshot(session) {
  const snapshot = session?.current_stage?.snapshot || {};
  const rows = [
    ["Stage", session?.current_stage?.name || "Waiting for a run."],
    ["Phase", session?.current_stage?.phase || session?.status || "idle"],
    ["Hosts seen", snapshot.subdomains || session?.summary?.subdomains || 0],
    ["Ports seen", snapshot.open_ports || session?.summary?.open_ports || 0],
    ["Web seen", snapshot.http_responses || session?.summary?.http_responses || 0]
  ];
  el("stage-snapshot").innerHTML = rows.map(([label, value]) => `
    <div class="snapshot-item">
      <span>${escapeHtml(label)}</span>
      <strong>${escapeHtml(String(value))}</strong>
    </div>
  `).join("");
}

function renderReports(session) {
  const artifacts = session?.artifacts || {};
  const links = [
    ["CLI report", "cli_report", "Fast terminal-friendly summary for quick operator review.", "Readable stream"],
    ["TXT report", "txt_report", "Plain-text export for notes, tickets, or lightweight sharing.", "Plain export"],
    ["HTML report", "html_report", "Human-readable report with the richest session context and presentation.", "Primary review"],
    ["JSON report", "json_report", "Structured export for scripting, pipelines, and downstream tooling.", "Automation ready"]
  ].filter(([, key]) => Boolean(artifacts[key]));

  el("report-links").innerHTML = links.map(([label, key, copy, meta]) => `
    <a class="button button-secondary report-card" target="_blank" rel="noopener" href="/reports/${encodeURIComponent(session.id)}/${key}">
      <span class="report-card-title">
        <span>${escapeHtml(label)}</span>
        <span class="status-pill completed">ready</span>
      </span>
      <span class="report-card-copy">${escapeHtml(copy)}</span>
      <span class="report-card-meta">${escapeHtml(meta)}</span>
    </a>
  `).join("") || '<div class="notice">Reports appear here after the first completed run.</div>';

  el("meta-reports").textContent = links.length > 0 ? `${links.length} ready` : "Awaiting";
}

function renderActivity(session) {
  const events = Array.isArray(session?.events) ? session.events.slice(-120) : [];
  el("activity-log").innerHTML = events.map((entry) => `
    <div class="activity-entry">
      <div class="activity-time">${escapeHtml(entry.timestamp ? new Date(entry.timestamp).toLocaleTimeString() : "--:--:--")}</div>
      <div>${escapeHtml(entry.message || entry.type || "event")}</div>
    </div>
  `).join("") || "<div class=\"activity-entry\"><div>No activity yet. Save a session and start a run to stream progress here.</div></div>";
  el("drawer-status").className = statusClass(session?.status);
  el("drawer-status").textContent = session?.status || "idle";
  el("drawer-stage").textContent = session?.current_stage?.name || "Waiting";
  el("activity-log").scrollTop = el("activity-log").scrollHeight;
}

function renderDetails(session) {
  const summary = session?.summary || {};
  const rows = [
    { item: "Scope posture", meaning: session?.config?.scope ? `Allowlist active: ${session.config.scope}` : "Primary target scope only.", recommendation: "Confirm exclusions before larger active runs." },
    { item: "Monitoring", meaning: session?.config?.monitor ? "Change tracking is enabled for drift analysis." : "Change tracking is disabled.", recommendation: session?.config?.monitor ? "Review the change summary after each run." : "Enable monitoring for repeat baselines." },
    { item: "Recon memory", meaning: session?.config?.memory ? "Known assets can be reused." : "Each run will re-check all assets.", recommendation: session?.config?.memory ? "Keep memory enabled for recurring targets." : "Enable memory to speed up repeat inventories." },
    { item: "Host coverage", meaning: `${summary.subdomains || 0} subdomains and ${summary.ips || 0} IPs were collected.`, recommendation: "Investigate high-signal hosts first and confirm ownership for shared infrastructure." },
    { item: "Service exposure", meaning: `${summary.open_ports || 0} open ports were recorded.`, recommendation: "Prioritize unusual ports and externally exposed management services." },
    { item: "Web exposure", meaning: `${summary.http_responses || 0} HTTP responses were fingerprinted.`, recommendation: "Open the HTML report to inspect technologies, routes, and captured artifacts." },
    { item: "Findings", meaning: `${summary.findings || 0} findings were generated.`, recommendation: "Validate critical and high findings first, then work through medium items." },
    { item: "Failure state", meaning: session?.error ? (session.error_details?.details || session.error) : "No blocking session crash was recorded.", recommendation: session?.error_details?.recommendation || "Review the activity log and fault-isolation notes if any engine warnings were recorded." },
    { item: "Framework integrity", meaning: session?.integrity?.summary || "No integrity issues were recorded for this session.", recommendation: (session?.integrity?.recommendations || [])[0] || "If the framework ever reports corruption, repair it before the next run." }
  ];

  el("detail-table").innerHTML = rows.map((row) => `
    <tr>
      <td>${escapeHtml(row.item)}</td>
      <td>${escapeHtml(row.meaning)}</td>
      <td>${escapeHtml(row.recommendation)}</td>
    </tr>
  `).join("");
}

function renderTopAssets(session) {
  const assets = Array.isArray(session?.payload?.top_assets) ? session.payload.top_assets.slice(0, 8) : [];
  el("top-assets-table").innerHTML = assets.map((asset) => `
    <tr>
      <td>${escapeHtml(asset.host || "-")}</td>
      <td><span class="score-badge">${escapeHtml(String(asset.total_score || 0))}</span></td>
      <td>${escapeHtml(Array(asset.matched_rules || []).join(", ") || "Interesting exposure patterns detected.")}</td>
    </tr>
  `).join("") || '<tr><td colspan="3">Top assets appear after a completed run.</td></tr>';
}

function renderFindings(session) {
  const findings = Array.isArray(session?.payload?.store?.findings) ? session.payload.store.findings.slice(0, 8) : [];
  el("findings-table").innerHTML = findings.map((finding) => `
    <tr>
      <td><span class="severity-badge ${escapeHtml(severityClass(finding.severity))}">${escapeHtml(String(finding.severity || "info").toUpperCase())}</span></td>
      <td>${escapeHtml(finding.title || "Untitled finding")}</td>
      <td>${escapeHtml(finding.host || "-")}</td>
    </tr>
  `).join("") || '<tr><td colspan="3">No findings recorded yet.</td></tr>';
}

function renderAbout() {
  el("about-copy").textContent = state.about || "ASRFacet-Rb";
  const banner = el("first-run-banner");
  if (!state.firstRun) {
    banner.classList.add("hidden");
    banner.textContent = "";
    return;
  }
  banner.classList.remove("hidden");
  banner.textContent = Array.isArray(state.firstRunGuide) ? state.firstRunGuide.join("\n") : "Welcome to ASRFacet-Rb.";
}

function showDoc(slug) {
  const doc = state.docs.find((entry) => entry.slug === slug) || state.docs[0];
  state.activeDoc = doc?.slug || null;
  el("docs-content").textContent = doc?.content || "Documentation is unavailable.";
  Array.from(document.querySelectorAll("[data-doc-slug]")).forEach((node) => {
    node.classList.toggle("active", node.getAttribute("data-doc-slug") === state.activeDoc);
  });
}

function renderDocs() {
  const query = state.docsQuery.trim().toLowerCase();
  const filteredDocs = state.docs.filter((doc) => {
    if (!query) return true;
    return [doc.title, doc.slug, doc.content].some((value) => String(value || "").toLowerCase().includes(query));
  });

  el("docs-nav").innerHTML = filteredDocs.map((doc) => `
    <button class="button button-secondary" data-doc-slug="${escapeHtml(doc.slug)}" type="button">${escapeHtml(doc.title)}</button>
  `).join("") || `<div class="notice">${state.docs.length > 0 ? "No documentation entries match the current search." : "Documentation files were not found."}</div>`;

  Array.from(document.querySelectorAll("[data-doc-slug]")).forEach((node) => {
    node.addEventListener("click", () => showDoc(node.getAttribute("data-doc-slug")));
  });

  const preferredDoc = filteredDocs.find((doc) => doc.slug === state.activeDoc) || filteredDocs[0];
  if (preferredDoc) {
    showDoc(preferredDoc.slug);
  } else {
    state.activeDoc = null;
    el("docs-content").textContent = state.docs.length > 0 ? "No documentation entries match the current search." : "Documentation is unavailable.";
  }
}

function renderOverview(session) {
  const config = session?.config || defaults;
  const rows = [
    ["Mode", modeLabel(config.mode)],
    ["Preferred report", String(config.format || "html").toUpperCase()],
    ["Threads", String(config.threads || 50)],
    ["Timeout", `${config.timeout || 10}s`],
    ["Scope", config.scope || "Primary target only"],
    ["Exclude", config.exclude || "None"]
  ];
  el("session-overview").innerHTML = rows.map(([label, value]) => `
    <div class="overview-item">
      <span>${escapeHtml(label)}</span>
      <strong>${escapeHtml(String(value))}</strong>
    </div>
  `).join("");
}

function syncChrome(session) {
  const config = session?.config || defaults;
  const sessionName = session?.name || "Session Builder";
  const target = config.target || "No target";
  const currentStage = session?.current_stage || {};
  el("current-heading").textContent = sessionName;
  el("current-subheading").textContent = `${target} | ${modeLabel(config.mode)} | ${session?.running ? "live run in progress" : "editable draft"}`;
  el("active-target").textContent = target;
  el("status-pill").className = statusClass(session?.status);
  el("status-pill").textContent = session?.status || "idle";
  el("heartbeat-label").textContent = session?.last_heartbeat_at ? relativeTime(session.last_heartbeat_at) : "Idle";
  el("stage-name").textContent = currentStage.name ? `${currentStage.name} (${currentStage.phase || "working"})` : "Waiting for a run.";
  el("hero-title").textContent = session?.running ? "Live session in progress" : "A more inspectable recon workspace";
  el("hero-copy").textContent = session?.running ? "The session is active. Use the activity drawer for the live feed while switching between workbench, reports, docs, and about views." : "This shell separates building, reviewing, and operating so the session mode feels closer to a control plane than a single long report page.";
}

function updateSummary(session) {
  const summary = Object.assign({ subdomains: 0, ips: 0, open_ports: 0, http_responses: 0, findings: 0 }, session?.summary || {});
  el("sum-subdomains").textContent = summary.subdomains || 0;
  el("sum-ips").textContent = summary.ips || 0;
  el("sum-ports").textContent = summary.open_ports || 0;
  el("sum-web").textContent = summary.http_responses || 0;
  el("sum-findings").textContent = summary.findings || 0;
  renderBarChart(summary);
  renderSnapshot(session || {});
  renderOverview(session || {});
  renderReports(session || {});
  renderActivity(session || {});
  renderDetails(session || {});
  renderTopAssets(session || {});
  renderFindings(session || {});
  syncChrome(session || currentDraft());
}

async function refreshSessions(preferredId, options = {}) {
  if (state.refreshInFlight) return;
  state.refreshInFlight = true;
  try {
    const data = await api("/api/sessions");
    state.sessions = Array.isArray(data.sessions) ? data.sessions : [];
    renderSessionList();
    const nextId = preferredId || state.current || state.sessions[0]?.id;
    const shouldReload = options.reloadCurrent !== false && !state.dirty;
    if (nextId && shouldReload) await loadSession(nextId, false);
  } finally {
    state.refreshInFlight = false;
  }
}

async function loadSession(id, promptOnDirty = true) {
  if (!id) return;
  if (promptOnDirty && state.dirty) {
    const shouldSave = window.confirm("This session has unsaved changes. Press OK to save before switching, or Cancel to stay on the current session.");
    if (!shouldSave) return;
    await saveSession(true);
  }
  const data = await api(`/api/session?id=${encodeURIComponent(id)}`);
  state.currentSession = data.session || null;
  state.current = state.currentSession?.id || id;
  fillForm(state.currentSession || { config: defaults });
  updateSummary(state.currentSession || {});
  renderSessionList();
}

async function saveSession(silent = false) {
  const data = await api("/api/sessions", { method: "POST", body: JSON.stringify(formData()) });
  if (!data.session) return;

  state.currentSession = data.session;
  state.current = data.session.id;
  state.dirty = false;
  const existingIndex = state.sessions.findIndex((item) => item.id === data.session.id);
  const summary = {
    id: data.session.id,
    name: data.session.name,
    status: data.session.status,
    running: data.session.running,
    target: data.session.config?.target,
    mode: data.session.config?.mode,
    updated_at: data.session.updated_at,
    last_heartbeat_at: data.session.last_heartbeat_at,
    summary: data.session.summary || {},
    current_stage: data.session.current_stage || {},
    artifacts: data.session.artifacts || {},
    error: data.session.error,
    error_details: data.session.error_details || {},
    integrity: data.session.integrity || {}
  };

  if (existingIndex >= 0) {
    state.sessions.splice(existingIndex, 1, summary);
  } else {
    state.sessions.unshift(summary);
  }

  renderSessionList();
  updateSummary(state.currentSession);
  updateSaveNote();
  if (!silent) window.alert("Session saved.");
}

async function runSession() {
  if (!state.current) await saveSession(true);
  if (!state.current) {
    window.alert("Save a session with a target first.");
    return;
  }
  const response = await api(`/api/run?id=${encodeURIComponent(state.current)}`, { method: "POST" });
  if (!response.ok) {
    window.alert("This session is already running or could not be started.");
    return;
  }
  state.dirty = false;
  updateSaveNote();
  await loadSession(state.current, false);
  setDrawerOpen(true);
}

function createSession() {
  state.current = null;
  state.currentSession = { name: "Untitled session", config: defaults };
  fillForm(state.currentSession);
  updateSummary(state.currentSession);
  state.dirty = true;
  updateSaveNote();
  switchView("sessions");
}

function saveDraftBeacon() {
  try {
    navigator.sendBeacon("/api/sessions", new Blob([JSON.stringify(formData())], { type: "application/json" }));
  } catch (_) {}
}

function updateSaveNote() {
  if (state.currentSession?.running) {
    el("save-note").textContent = "Active run";
    return;
  }
  el("save-note").textContent = state.dirty ? "Unsaved changes" : "Clean draft";
}

function markDirty() {
  state.dirty = true;
  renderBuilderNotes(formData());
  renderCommandPreview(formData());
  syncChrome(Object.assign({}, currentDraft(), formData()));
  updateSaveNote();
  clearTimeout(state.autosaveTimer);
  state.autosaveTimer = setTimeout(() => { saveSession(true).catch(() => null); }, 700);
}

function attachListeners() {
  fields.forEach((id) => {
    const node = el(id);
    const eventName = node && node.type === "checkbox" ? "change" : "input";
    node?.addEventListener(eventName, markDirty);
  });

  el("save-session").addEventListener("click", () => saveSession());
  el("run-session").addEventListener("click", () => runSession());
  el("new-session").addEventListener("click", () => createSession());
  el("refresh-sessions").addEventListener("click", () => refreshSessions(state.current));
  el("open-activity").addEventListener("click", () => setDrawerOpen(true));
  el("close-activity").addEventListener("click", () => setDrawerOpen(false));
  el("drawer-backdrop").addEventListener("click", () => setDrawerOpen(false));
  el("sidebar-toggle").addEventListener("click", () => setSidebarOpen(true));
  el("sidebar-backdrop").addEventListener("click", () => setSidebarOpen(false));
  el("session-search").addEventListener("input", (event) => {
    state.sessionQuery = event.target.value || "";
    renderSessionList();
  });
  document.querySelectorAll("[data-session-filter]").forEach((node) => {
    node.addEventListener("click", () => {
      state.sessionFilter = node.getAttribute("data-session-filter") || "all";
      document.querySelectorAll("[data-session-filter]").forEach((button) => {
        button.classList.toggle("active", button === node);
      });
      renderSessionList();
    });
  });
  el("docs-search").addEventListener("input", (event) => {
    state.docsQuery = event.target.value || "";
    renderDocs();
  });

  document.querySelectorAll("[data-view]").forEach((node) => {
    node.addEventListener("click", () => switchView(node.getAttribute("data-view")));
  });
  document.querySelectorAll("[data-form-tab]").forEach((node) => {
    node.addEventListener("click", () => switchFormTab(node.getAttribute("data-form-tab")));
  });

  window.addEventListener("beforeunload", (event) => {
    if (!state.dirty && !(state.currentSession && state.currentSession.running)) return;
    saveDraftBeacon();
    event.preventDefault();
    event.returnValue = "";
  });

  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") saveDraftBeacon();
  });
}

async function bootstrap() {
  const data = await api("/api/bootstrap");
  state.bootstrap = data.server || {};
  state.about = data.about || "";
  state.docs = Array.isArray(data.docs) ? data.docs : [];
  state.firstRun = data.first_run === true;
  state.firstRunGuide = Array.isArray(data.first_run_guide) ? data.first_run_guide : [];
  state.sessions = Array.isArray(data.sessions) ? data.sessions : [];

  el("session-root").textContent = state.bootstrap.sessions_root || "Unavailable";
  el("report-root").textContent = state.bootstrap.reports_root || "Unavailable";

  renderSessionList();
  renderAbout();
  renderDocs();
  attachListeners();
  switchFormTab("target");
  switchView("workbench");

  if (state.sessions[0]?.id) {
    await loadSession(state.sessions[0].id, false);
  } else {
    createSession();
  }

  updateSaveNote();
  setInterval(() => { refreshSessions(state.current).catch(() => null); }, 2500);
}

bootstrap().catch(() => {
  el("activity-log").innerHTML = "<div class=\"activity-entry\"><div>Unable to initialize the control panel.</div></div>";
});
