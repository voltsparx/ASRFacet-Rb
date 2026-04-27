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
  theme: "light",
  bootstrap: {},
  capabilities: {},
  selectedGraphNode: null
};

const fields = [
  "name",
  "target",
  "mode",
  "format",
  "plugins",
  "filters",
  "ports",
  "threads",
  "timeout",
  "delay",
  "scan-type",
  "raw-backend",
  "scan-timing",
  "scan-version",
  "scan-os",
  "scan-intensity",
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

const artifactCatalog = {
  cli_report: ["CLI report", "Fast terminal-friendly summary for quick operator review.", "Readable stream"],
  txt_report: ["TXT report", "Plain-text export for notes, tickets, or lightweight sharing.", "Plain export"],
  html_report: ["HTML report", "Human-readable report with the richest session context and presentation.", "Primary review"],
  json_report: ["JSON report", "Structured export for scripting, pipelines, and downstream tooling.", "Automation ready"],
  pdf_report: ["PDF report", "Printable dark-theme report with charts, tables, and summary cards.", "Presentation ready"],
  docx_report: ["DOCX report", "Editable report bundle for document workflows and formal handoff.", "Document workflow"],
  sarif_report: ["SARIF report", "Static-analysis friendly export for CI, tooling, and evidence pipelines.", "Tooling export"],
  csv_subdomains_report: ["CSV subdomains", "Tabular subdomain export with metadata header rows.", "Data slice"],
  csv_ips_report: ["CSV IPs", "Tabular IP inventory with class and port context.", "Data slice"],
  csv_ports_report: ["CSV ports", "Tabular service exposure export for network review.", "Data slice"],
  csv_findings_report: ["CSV findings", "Flat findings export for ticketing and triage.", "Data slice"],
  csv_js_endpoints_report: ["CSV JS endpoints", "JavaScript endpoint inventory for app review.", "Data slice"]
};

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
    ports: "Ports only",
    portscan: "Scanner engine"
  }[String(mode || "scan")] || String(mode || "scan");
}

function quoteShell(value) {
  if (!value) return "";
  return /\s/.test(value) ? `"${String(value).replace(/"/g, '\\"')}"` : String(value);
}

function resolveTheme() {
  try {
    const persisted = window.localStorage.getItem("asrfacet-rb-theme");
    if (persisted === "light" || persisted === "dark") return persisted;
  } catch (_) {}
  return "light";
}

function applyTheme(theme) {
  state.theme = theme === "dark" ? "dark" : "light";
  document.body.classList.toggle("theme-dark", state.theme === "dark");
  document.body.classList.toggle("theme-light", state.theme !== "dark");
  el("theme-toggle").textContent = state.theme === "dark" ? "Light Mode" : "Dark Mode";
  try {
    window.localStorage.setItem("asrfacet-rb-theme", state.theme);
  } catch (_) {}
}

function toggleTheme() {
  applyTheme(state.theme === "dark" ? "light" : "dark");
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
  if (view === "graph") renderGraph(state.currentSession || currentDraft());
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

function normalizedStore(session) {
  const store = session?.payload?.store;
  return store && typeof store === "object" ? store : {};
}

function summaryFor(session) {
  return Object.assign({ subdomains: 0, ips: 0, open_ports: 0, http_responses: 0, findings: 0 }, session?.summary || {});
}

function formData() {
  return {
    id: state.current,
    name: el("name").value.trim(),
    config: {
      target: el("target").value.trim(),
      mode: el("mode").value,
      format: el("format").value,
      plugins: el("plugins").value.trim(),
      filters: el("filters").value.trim(),
      ports: el("ports").value.trim(),
      threads: Number(el("threads").value || 50),
      timeout: Number(el("timeout").value || 10),
      delay: Number(el("delay").value || 0),
      scan_type: el("scan-type").value,
      raw_backend: el("raw-backend").value,
      scan_timing: Number(el("scan-timing").value || 3),
      scan_version: el("scan-version").checked,
      scan_os: el("scan-os").checked,
      scan_intensity: Number(el("scan-intensity").value || 7),
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
  return state.currentSession || { name: "Untitled session", config: defaults, summary: {}, payload: { store: {} } };
}

function fillForm(session) {
  const config = Object.assign({}, defaults, session?.config || {});
  el("name").value = session?.name || "Untitled session";
  el("target").value = config.target || "";
  el("mode").value = config.mode || "scan";
  el("format").value = config.format || "html";
  el("plugins").value = config.plugins || "";
  el("filters").value = config.filters || "";
  el("ports").value = config.ports || "top100";
  el("threads").value = config.threads || 50;
  el("timeout").value = config.timeout || 10;
  el("delay").value = config.delay || 0;
  el("scan-type").value = config.scan_type || "connect";
  el("raw-backend").value = config.raw_backend || "auto";
  el("scan-timing").value = config.scan_timing ?? 3;
  el("scan-version").checked = config.scan_version === true;
  el("scan-os").checked = config.scan_os === true;
  el("scan-intensity").value = config.scan_intensity ?? 7;
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
  state.selectedGraphNode = null;
  syncModeControls();
  renderExtensionCatalog("plugins");
  renderExtensionCatalog("filters");
  renderExtensionResolution({ config });
  renderBuilderNotes(formData());
  renderCommandPreview(formData());
  syncChrome(session || currentDraft());
}

function buildCommandPreview(payload) {
  const config = payload?.config || defaults;
  const target = quoteShell(config.target || "TARGET");
  const parts = ["asrfacet-rb"];
  const format = String(config.format || "html");

  switch (config.mode) {
    case "portscan":
      parts.push("portscan", target);
      parts.push("--type", config.scan_type || "connect");
      parts.push("--timing", String(config.scan_timing ?? 3));
      if (format !== "cli") parts.push("--format", format);
      if (config.plugins) parts.push("--plugins", quoteShell(config.plugins));
      if (config.filters) parts.push("--filters", quoteShell(config.filters));
      if (config.raw_backend && config.raw_backend !== "auto") parts.push("--raw-backend", config.raw_backend);
      if (config.scan_version) parts.push("--version");
      if (config.scan_os) parts.push("--os");
      if (Number(config.scan_intensity ?? 7) !== 7) parts.push("--intensity", String(config.scan_intensity));
      if (config.ports && config.ports !== "top100") parts.push("--ports", quoteShell(config.ports));
      if (Number(config.verbose ? 1 : 0) > 0) parts.push("--verbosity", "1");
      return parts.join(" ");
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

  if (format !== "cli") parts.push("--format", format);
  if (config.plugins) parts.push("--plugins", quoteShell(config.plugins));
  if (config.filters) parts.push("--filters", quoteShell(config.filters));
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
  const scannerMode = String(config.mode) === "portscan";
  const rawMode = ["syn", "ack", "fin", "null", "xmas", "window", "maimon"].includes(String(config.scan_type || ""));
  const caps = state.capabilities || {};
  const pluginPlan = resolveSelection("plugins", config.plugins || "", config.mode || "scan");
  const filterPlan = resolveSelection("filters", config.filters || "", config.mode || "scan");
  const runtimeHint = scannerMode && rawMode ?
    (caps.nping_available ? `Raw backend ${config.raw_backend || "auto"} can use the installed packet backend on ${caps.platform || "this host"}.` : `Raw scan types need an external packet backend. ${caps.raw_scan_requirements || ""}`.trim()) :
    `Preferred output is ${labelForFormat(config.format || "html")} and the terminal preview stays aligned with the saved session.`;
  const notes = [
    {
      title: "Target posture",
      copy: config.target ? `Current target is ${config.target}. ${config.scope ? "An explicit allowlist is active." : "No extra allowlist is configured yet."}` : "No target is selected yet. Add a hostname or IP before saving or running."
    },
    {
      title: "Execution profile",
      copy: scannerMode ?
        `${modeLabel(config.mode)} runs ${config.scan_type || "connect"} with T${config.scan_timing ?? 3}, ${config.timeout || 10}s timeout, and ${Number(config.delay || 0) > 0 ? `${config.delay}ms base delay.` : "no base delay."}` :
        `${modeLabel(config.mode)} mode with ${config.threads || 50} threads and ${config.timeout || 10}s timeout. ${Number(config.delay || 0) > 0 ? `Base delay is ${config.delay}ms.` : "No base delay is configured."}`
    },
    {
      title: "Runtime fit",
      copy: scannerMode ?
        `${config.scan_version ? "version detection is enabled" : "version detection is disabled"}, ${config.scan_os ? "OS detection is enabled" : "OS detection is disabled"}, intensity is ${config.scan_intensity ?? 7}, and raw backend is ${config.raw_backend || "auto"}.` :
        `${config.monitor ? "Monitoring is on" : "Monitoring is off"}, ${config.memory ? "recon memory is on" : "recon memory is off"}, ${config.headless ? "headless rendering is enabled" : "headless rendering is disabled"}, and ${config.adaptive_rate ? "adaptive rate control is active." : "adaptive rate control is disabled."}`
    },
    {
      title: "Capability check",
      copy: runtimeHint
    },
    {
      title: "Extension packs",
      copy: `${pluginPlan.selected.length > 0 ? `Plugins: ${pluginPlan.selected.map((entry) => entry.name).join(", ")}.` : "No session plugins selected yet."} ${filterPlan.selected.length > 0 ? `Filters: ${filterPlan.selected.map((entry) => entry.name).join(", ")}.` : "No session filters selected yet."} ${(pluginPlan.unknown.length + filterPlan.unknown.length) > 0 ? "One or more selectors do not match the current mode catalog." : "Selectors are compatible with the current mode."}`
    }
  ];

  el("builder-notes").innerHTML = notes.map((note) => `
    <div class="builder-note">
      <span>${escapeHtml(note.title)}</span>
      <strong>${escapeHtml(note.copy)}</strong>
    </div>
  `).join("");
}

function syncModeControls() {
  const scannerMode = el("mode").value === "portscan";
  document.querySelectorAll(".scanner-only").forEach((node) => {
    node.classList.toggle("hidden", !scannerMode);
  });
  renderExtensionCatalog("plugins");
  renderExtensionCatalog("filters");
  renderExtensionResolution(formData());
}

function labelForMode(mode) {
  return {
    scan: "Full scan",
    passive: "Passive",
    dns: "DNS only",
    ports: "Ports only",
    portscan: "Scanner engine"
  }[mode] || mode;
}

function labelForFormat(format) {
  return {
    cli: "CLI",
    json: "JSON",
    html: "HTML",
    txt: "TXT",
    csv: "CSV",
    pdf: "PDF",
    docx: "DOCX",
    all: "All formats",
    sarif: "SARIF"
  }[format] || String(format || "").toUpperCase();
}

function renderSelectOptions(selectId, values, labelFn) {
  const node = el(selectId);
  if (!node || !Array.isArray(values) || values.length === 0) return;
  const selectedValue = node.value;
  node.innerHTML = values.map((value) => `<option value="${escapeHtml(String(value))}">${escapeHtml(labelFn(value))}</option>`).join("");
  if (values.map(String).includes(String(selectedValue))) {
    node.value = String(selectedValue);
  }
}

function normalizeSelectorToken(value) {
  return String(value || "").trim().toLowerCase();
}

function parseSelectionString(value) {
  const include = [];
  const exclude = [];
  String(value || "").split(",").map((entry) => normalizeSelectorToken(entry)).filter(Boolean).forEach((token) => {
    if (token.startsWith("-") || token.startsWith("!")) {
      exclude.push(token.replace(/^[-!]+/, ""));
    } else {
      include.push(token);
    }
  });
  return { include, exclude };
}

function catalogEntries(kind, mode) {
  const key = kind === "filters" ? "filters_catalog" : "plugins_catalog";
  const entries = Array.isArray(state.capabilities?.[key]) ? state.capabilities[key] : [];
  const normalizedMode = normalizeSelectorToken(mode);
  if (!normalizedMode) return entries;
  return entries.filter((entry) => Array.isArray(entry.modes) ? entry.modes.map(normalizeSelectorToken).includes(normalizedMode) : true);
}

function entryMatchesSelector(entry, token) {
  const normalized = normalizeSelectorToken(token);
  const aliases = Array.isArray(entry.aliases) ? entry.aliases.map(normalizeSelectorToken) : [];
  const tags = Array.isArray(entry.tags) ? entry.tags.map(normalizeSelectorToken) : [];
  const modes = Array.isArray(entry.modes) ? entry.modes.map(normalizeSelectorToken) : [];
  return normalized === normalizeSelectorToken(entry.name) ||
    aliases.includes(normalized) ||
    normalized === `category:${normalizeSelectorToken(entry.category)}` ||
    (normalized.startsWith("mode:") && modes.includes(normalized.replace(/^mode:/, ""))) ||
    (normalized.startsWith("tag:") && tags.includes(normalized.replace(/^tag:/, ""))) ||
    normalized === "all";
}

function resolveSelection(kind, selection, mode) {
  const entries = catalogEntries(kind, mode);
  const parsed = parseSelectionString(selection);
  const selectTokens = parsed.include;
  const excludeTokens = parsed.exclude;
  const selected = [];
  const excluded = [];
  const unknown = [];

  const matchTokens = (tokens, collector) => {
    tokens.forEach((token) => {
      if (token === "all") {
        collector.push(...entries);
        return;
      }
      const matches = entries.filter((entry) => entryMatchesSelector(entry, token));
      if (matches.length === 0) {
        unknown.push(token);
      } else {
        collector.push(...matches);
      }
    });
  };

  matchTokens(selectTokens, selected);
  matchTokens(excludeTokens, excluded);
  const selectedNames = new Set((selectTokens.length === 0 || selectTokens.includes("all") ? entries : selected).map((entry) => entry.name));
  excluded.forEach((entry) => selectedNames.delete(entry.name));

  return {
    entries,
    selected: entries.filter((entry) => selectedNames.has(entry.name)),
    excluded: entries.filter((entry) => excluded.some((blocked) => blocked.name === entry.name)),
    unknown: Array.from(new Set(unknown))
  };
}

function updateDelimitedSelection(fieldId, name) {
  const node = el(fieldId);
  const token = normalizeSelectorToken(name);
  const values = String(node.value || "").split(",").map((entry) => normalizeSelectorToken(entry)).filter(Boolean);
  const existing = new Set(values);
  if (existing.has(token)) {
    existing.delete(token);
  } else {
    existing.add(token);
  }
  node.value = Array.from(existing).join(",");
  markDirty();
}

function renderExtensionCatalog(kind) {
  const mode = el("mode")?.value || defaults.mode || "scan";
  const fieldId = kind === "filters" ? "filters" : "plugins";
  const container = el(kind === "filters" ? "filters-catalog" : "plugins-catalog");
  if (!container) return;
  const resolution = resolveSelection(kind, el(fieldId).value, mode);
  const grouped = resolution.entries.reduce((memo, entry) => {
    const key = entry.category || "general";
    memo[key] ||= [];
    memo[key].push(entry);
    return memo;
  }, {});

  container.innerHTML = Object.keys(grouped).sort().map((category) => `
    <div class="extension-group">
      <div class="extension-group-head">
        <strong>${escapeHtml(category)}</strong>
        <span>${escapeHtml(String(grouped[category].length))} available</span>
      </div>
      <div class="extension-chip-row">
        ${grouped[category].map((entry) => `
          <button class="extension-chip ${resolution.selected.some((selected) => selected.name === entry.name) ? "active" : ""}" data-extension-kind="${escapeHtml(kind)}" data-extension-name="${escapeHtml(entry.name)}" type="button" title="${escapeHtml(entry.description || "")}">
            ${escapeHtml(entry.title || entry.name)}
            <small>${escapeHtml((entry.modes || []).join(", "))}</small>
          </button>
        `).join("")}
      </div>
    </div>
  `).join("") || `<div class="notice">No ${escapeHtml(kind)} are available for ${escapeHtml(mode)} mode.</div>`;

  Array.from(container.querySelectorAll("[data-extension-name]")).forEach((node) => {
    node.addEventListener("click", () => updateDelimitedSelection(fieldId, node.getAttribute("data-extension-name")));
  });
}

function renderExtensionResolution(payload) {
  const config = payload?.config || defaults;
  const pluginPlan = resolveSelection("plugins", config.plugins || "", config.mode || "scan");
  const filterPlan = resolveSelection("filters", config.filters || "", config.mode || "scan");
  const selectorHelp = Array.isArray(state.capabilities?.selector_help) ? state.capabilities.selector_help.join(", ") : "all, name, category:<name>, mode:<mode>, -name";
  el("extension-resolution").innerHTML = [
    `<strong>Plugins:</strong> ${pluginPlan.selected.length > 0 ? escapeHtml(pluginPlan.selected.map((entry) => entry.name).join(", ")) : "none selected"}`,
    `<strong>Filters:</strong> ${filterPlan.selected.length > 0 ? escapeHtml(filterPlan.selected.map((entry) => entry.name).join(", ")) : "none selected"}`,
    pluginPlan.unknown.length > 0 ? `<strong>Unknown plugin selectors:</strong> ${escapeHtml(pluginPlan.unknown.join(", "))}` : "",
    filterPlan.unknown.length > 0 ? `<strong>Unknown filter selectors:</strong> ${escapeHtml(filterPlan.unknown.join(", "))}` : "",
    `<strong>Selector syntax:</strong> ${escapeHtml(selectorHelp)}`
  ].filter(Boolean).join("<br>");
}

function applyCapabilities(capabilities) {
  const caps = capabilities || {};
  renderSelectOptions("mode", caps.modes || [], labelForMode);
  renderSelectOptions("format", caps.formats || [], labelForFormat);
  renderSelectOptions("scan-type", caps.scan_types || [], (value) => value);
  renderSelectOptions("raw-backend", caps.raw_backends || [], (value) => value);
  renderSelectOptions("scan-timing", caps.scan_timings || [], (value) => `T${value}`);
  renderSelectOptions("webhook-platform", caps.webhook_platforms || [], (value) => String(value || "").charAt(0).toUpperCase() + String(value || "").slice(1));
  renderExtensionCatalog("plugins");
  renderExtensionCatalog("filters");
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
        <div><span class="eyebrow">Target</span><div>${escapeHtml(session.target || "No target yet")}</div></div>
        <div><span class="eyebrow">Mode</span><div>${escapeHtml(modeLabel(session.mode || "scan"))}</div></div>
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
      <div class="bar-unit-meter" style="height:${Math.max(24, Math.round((Number(value || 0) / max) * 160))}px"></div>
      <strong>${escapeHtml(String(value || 0))}</strong>
      <div class="bar-unit-label">${escapeHtml(label)}</div>
    </div>
  `).join("");
}

function renderDonutChart(session) {
  const summary = summaryFor(session);
  const items = [
    { label: "Subdomains", value: summary.subdomains || 0, color: "#d72626" },
    { label: "Ports", value: summary.open_ports || 0, color: "#f2994a" },
    { label: "Web", value: summary.http_responses || 0, color: "#2d9cdb" },
    { label: "Findings", value: summary.findings || 0, color: "#27ae60" }
  ];
  const total = items.reduce((sum, item) => sum + Number(item.value || 0), 0);
  let cursor = 0;
  const stops = items.map((item) => {
    const percent = total > 0 ? (item.value / total) * 100 : 25;
    const start = cursor;
    cursor += percent;
    return `${item.color} ${start.toFixed(2)}% ${cursor.toFixed(2)}%`;
  }).join(", ");

  el("donut-chart").innerHTML = `
    <div class="donut-shell">
      <div class="donut-ring" style="background: conic-gradient(${stops});">
        <div class="donut-center">
          <div>
            <strong>${escapeHtml(String(total))}</strong>
            <div class="nav-hint">Tracked units</div>
          </div>
        </div>
      </div>
      <div class="donut-legend">
        ${items.map((item) => `
          <div class="donut-legend-item">
            <span class="legend-swatch" style="background:${escapeHtml(item.color)};"></span>
            <span>${escapeHtml(item.label)} <strong>${escapeHtml(String(item.value))}</strong></span>
          </div>
        `).join("")}
      </div>
    </div>
  `;
}

function buildTrendSeries(session) {
  const events = Array.isArray(session?.events) ? session.events.slice(-10) : [];
  if (events.length > 0) {
    let running = 0;
    return events.map((entry, index) => {
      if (String(entry.type || "").toLowerCase() === "finding") running += 2;
      else if (String(entry.type || "").toLowerCase() === "stage") running += 3;
      else running += 1;
      return {
        label: String(index + 1),
        value: running
      };
    });
  }

  const summary = summaryFor(session);
  return [
    { label: "Seed", value: 0 },
    { label: "Hosts", value: Number(summary.subdomains || 0) },
    { label: "IPs", value: Number(summary.ips || 0) },
    { label: "Ports", value: Number(summary.open_ports || 0) },
    { label: "Web", value: Number(summary.http_responses || 0) },
    { label: "Find", value: Number(summary.findings || 0) }
  ];
}

function renderTrendChart(session) {
  const points = buildTrendSeries(session);
  const width = 620;
  const height = 240;
  const padX = 28;
  const padY = 26;
  const max = Math.max(1, ...points.map((point) => Number(point.value || 0)));
  const step = points.length > 1 ? (width - padX * 2) / (points.length - 1) : 0;
  const coords = points.map((point, index) => {
    const x = padX + index * step;
    const y = height - padY - ((Number(point.value || 0) / max) * (height - padY * 2));
    return { x, y, label: point.label, value: point.value };
  });
  const polyline = coords.map((point) => `${point.x},${point.y}`).join(" ");
  const area = [`${padX},${height - padY}`, ...coords.map((point) => `${point.x},${point.y}`), `${coords[coords.length - 1]?.x || padX},${height - padY}`].join(" ");

  el("trend-chart").innerHTML = `
    <div class="trend-shell">
      <svg viewBox="0 0 ${width} ${height}" aria-label="Trend chart">
        <line class="trend-axis" x1="${padX}" y1="${height - padY}" x2="${width - padX}" y2="${height - padY}"></line>
        <line class="trend-axis" x1="${padX}" y1="${padY}" x2="${padX}" y2="${height - padY}"></line>
        ${[0.25, 0.5, 0.75].map((ratio) => {
          const y = height - padY - ((height - padY * 2) * ratio);
          return `<line class="trend-gridline" x1="${padX}" y1="${y}" x2="${width - padX}" y2="${y}"></line>`;
        }).join("")}
        <polygon class="trend-area" points="${area}"></polygon>
        <polyline class="trend-line" points="${polyline}"></polyline>
        ${coords.map((point) => `<circle class="trend-dot" cx="${point.x}" cy="${point.y}" r="4"></circle>`).join("")}
        ${coords.map((point) => `<text class="trend-label" x="${point.x}" y="${height - 8}" text-anchor="middle">${escapeHtml(point.label)}</text>`).join("")}
      </svg>
    </div>
  `;
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
  const readyCount = Object.keys(artifactCatalog).filter((key) => Boolean(artifacts[key])).length;
  const reportWarnings = Array.isArray(artifacts.report_errors) ? artifacts.report_errors : [];
  const links = Object.entries(artifactCatalog)
    .filter(([key]) => Boolean(artifacts[key]))
    .map(([key, [label, copy, meta]]) => [label, key, copy, meta]);

  el("report-summary").innerHTML = [
    ["Preferred output", labelForFormat(session?.config?.format || "html")],
    ["Report engine", session?.payload?.meta?.report_engine || session?.meta?.report_engine || "ASRFacet-Rb"],
    ["Artifacts ready", String(readyCount)],
    ["Render warnings", reportWarnings.length > 0 ? String(reportWarnings.length) : "None"]
  ].map(([label, value]) => `
    <div class="summary-tile">
      <span>${escapeHtml(label)}</span>
      <strong>${escapeHtml(value)}</strong>
    </div>
  `).join("");

  el("report-links").innerHTML = links.map(([label, key, copy, meta]) => `
    <a class="button button-secondary report-card" target="_blank" rel="noopener" href="/reports/${encodeURIComponent(session.id)}/${key}">
      <span class="report-card-title">
        <span>${escapeHtml(label)}</span>
        <span class="status-pill completed">ready</span>
      </span>
      <span class="report-card-copy">${escapeHtml(copy)}</span>
      <span class="report-card-meta">${escapeHtml(meta)}</span>
    </a>
  `).join("");

  if (reportWarnings.length > 0) {
    el("report-links").innerHTML += reportWarnings.map((warning) => `
      <div class="notice">
        <strong>${escapeHtml(String(warning.format || "report").toUpperCase())} warning</strong>
        <div>${escapeHtml(warning.message || "A renderer reported a recoverable issue.")}</div>
      </div>
    `).join("");
  }

  if (!el("report-links").innerHTML.trim()) {
    el("report-links").innerHTML = '<div class="notice">Reports appear here after the first completed run.</div>';
  }

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
  const summary = summaryFor(session);
  const rows = [
    { item: "Scope posture", meaning: session?.config?.scope ? `Allowlist active: ${session.config.scope}` : "Primary target scope only.", recommendation: "Confirm exclusions before larger active runs." },
    { item: "Monitoring", meaning: session?.config?.monitor ? "Change tracking is enabled for drift analysis." : "Change tracking is disabled.", recommendation: session?.config?.monitor ? "Review the delta summary after each run." : "Enable monitoring for repeat baselines." },
    { item: "Recon memory", meaning: session?.config?.memory ? "Known assets can be reused." : "Each run will re-check all assets.", recommendation: session?.config?.memory ? "Keep memory enabled for recurring targets." : "Enable memory to speed up repeat inventories." },
    { item: "Host coverage", meaning: `${summary.subdomains || 0} subdomains and ${summary.ips || 0} IPs were collected.`, recommendation: "Investigate high-signal hosts first and confirm ownership for shared infrastructure." },
    { item: "Service exposure", meaning: `${summary.open_ports || 0} open ports were recorded.`, recommendation: "Prioritize unusual ports and externally exposed management services." },
    { item: "Web exposure", meaning: `${summary.http_responses || 0} HTTP responses were fingerprinted.`, recommendation: "Open the HTML report to inspect technologies, routes, and captured artifacts." },
    { item: "Findings", meaning: `${summary.findings || 0} findings were generated.`, recommendation: "Validate critical and high findings first, then work through medium items." },
    { item: "Failure state", meaning: session?.error ? (session.error_details?.details || session.error) : "No blocking session crash was recorded.", recommendation: session?.error_details?.recommendation || "Review the activity log and fault-isolation notes if any engine warnings were recorded." },
    { item: "Framework integrity", meaning: session?.integrity?.summary || "No integrity issues were recorded for this session.", recommendation: (session?.integrity?.recommendations || [])[0] || "Repair the framework before the next run if integrity issues appear." }
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
  const findings = Array.isArray(normalizedStore(session).findings) ? normalizedStore(session).findings.slice(0, 8) : [];
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
    ["Scanner", config.mode === "portscan" ? `${config.scan_type || "connect"} / T${config.scan_timing ?? 3}` : "Pipeline-managed"],
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

function renderControlPlane(session) {
  const caps = state.capabilities || {};
  const config = session?.config || defaults;
  const tiles = [
    ["Platform", caps.platform || "Unknown host", caps.raw_scan_requirements || "Capability details unavailable."],
    ["Report engine", session?.payload?.meta?.report_engine || session?.meta?.report_engine || "ASRFacet-Rb", "Rendered artifacts inherit the current runtime detector choice."],
    ["Packet backend", caps.nping_available ? "Nping ready" : "Fallback only", caps.nping_available ? "Raw-style scans can use the packet backend when privileges are available." : "Connect-safe workflows remain available even when raw scans are not."],
    ["Elevation", caps.elevation_supported ? "Available" : "Unavailable", caps.elevation_supported ? "The host can relaunch privileged scans when needed." : "Use connect-oriented scans or run the terminal manually with elevated privileges."],
    ["Current scan", config.mode === "portscan" ? `${config.scan_type || "connect"} / ${config.raw_backend || "auto"}` : "Pipeline-managed", config.mode === "portscan" ? "Scanner controls are active for this session." : "Pipeline and focused modes use saved builder settings."],
    ["Actions", Array.isArray(caps.session_actions) ? caps.session_actions.join(", ") : "save, run", "Lifecycle controls stay mirrored between the terminal and browser control plane."],
    ["Extension packs", `${(caps.plugins || []).length} plugins / ${(caps.filters || []).length} filters`, `Built-ins: ${(caps.plugins || []).join(", ") || "none"} | ${(caps.filters || []).join(", ") || "none"}`]
  ];

  el("control-plane-grid").innerHTML = tiles.map(([label, value, meta]) => `
    <div class="control-tile">
      <span>${escapeHtml(label)}</span>
      <strong>${escapeHtml(String(value))}</strong>
      <code>${escapeHtml(String(meta))}</code>
    </div>
  `).join("");
}

function trimList(values, limit = 5) {
  return Array.from(new Set(Array.isArray(values) ? values.filter(Boolean) : [])).slice(0, limit);
}

function extractGraphModel(session) {
  const store = normalizedStore(session);
  const target = session?.config?.target || "target";
  const hosts = trimList(store.subdomains || [target], 5);
  const ips = trimList(store.ips, 4);
  const ports = trimList((store.open_ports || []).map((entry) => `${entry.host || target}:${entry.port || "?"}`), 5);
  const findings = trimList((store.findings || []).map((entry) => entry.title || entry.host || "Finding"), 4);

  const nodes = [];
  const edges = [];
  const stats = summaryFor(session);
  const columns = {
    target: { x: 120 },
    host: { x: 330 },
    service: { x: 560 },
    finding: { x: 790 }
  };

  nodes.push({
    id: "target",
    label: target,
    type: "target",
    x: columns.target.x,
    y: 280,
    title: "Primary target",
    detail: `This is the current session target. The session has ${stats.subdomains || 0} discovered hosts and ${stats.open_ports || 0} open ports.`,
    recommendations: ["Validate scope and exclusions before starting broader active work."]
  });

  hosts.forEach((host, index) => {
    const nodeId = `host-${index}`;
    nodes.push({
      id: nodeId,
      label: host,
      type: "host",
      x: columns.host.x,
      y: 110 + (index * 90),
      title: "Discovered host",
      detail: `${host} is part of the collected host surface for this session.`,
      recommendations: ["Open the HTML or JSON report to inspect linked services and findings for this host."]
    });
    edges.push({ from: "target", to: nodeId });
  });

  ports.forEach((service, index) => {
    const nodeId = `service-${index}`;
    nodes.push({
      id: nodeId,
      label: service,
      type: "service",
      x: columns.service.x,
      y: 150 + (index * 80),
      title: "Observed service",
      detail: `${service} represents a reachable network service observed in the current result set.`,
      recommendations: ["Use service output and banner data first, then move into HTTP or certificate review when applicable."]
    });
    edges.push({ from: hosts[index % Math.max(1, hosts.length)] ? `host-${index % Math.max(1, hosts.length)}` : "target", to: nodeId });
  });

  findings.forEach((finding, index) => {
    const nodeId = `finding-${index}`;
    nodes.push({
      id: nodeId,
      label: finding,
      type: "finding",
      x: columns.finding.x,
      y: 180 + (index * 90),
      title: "Generated finding",
      detail: `${finding} is a heuristic or correlated issue worth manual validation.`,
      recommendations: ["Confirm severity and ownership before escalating or ticketing the finding."]
    });
    edges.push({ from: ports[index % Math.max(1, ports.length)] ? `service-${index % Math.max(1, ports.length)}` : "target", to: nodeId });
  });

  ips.slice(0, 3).forEach((ip, index) => {
    const nodeId = `ip-${index}`;
    nodes.push({
      id: nodeId,
      label: ip,
      type: "host",
      x: columns.host.x,
      y: 390 + (index * 70),
      title: "Resolved IP",
      detail: `${ip} is a resolved or directly scanned IP tied to this session.`,
      recommendations: ["Check ownership and hosting context before treating shared infrastructure as fully in scope."]
    });
    edges.push({ from: "target", to: nodeId });
  });

  return { nodes, edges };
}

function buildGraphSelection(model, selectedId) {
  const selectedNode = model.nodes.find((node) => node.id === selectedId) || model.nodes[0];
  const connectedIds = new Set([selectedNode?.id].filter(Boolean));
  model.edges.forEach((edge) => {
    if (edge.from === selectedNode?.id || edge.to === selectedNode?.id) {
      connectedIds.add(edge.from);
      connectedIds.add(edge.to);
    }
  });

  return { selectedNode, connectedIds };
}

function renderGraphFocus(session, model, selection) {
  const summary = summaryFor(session);
  const selectedNode = selection.selectedNode;
  const linkedNodes = model.nodes.filter((node) => selection.connectedIds.has(node.id) && node.id !== selectedNode?.id);

  if (!selectedNode) {
    el("graph-focus").innerHTML = `
      <div class="focus-block">
        <div class="eyebrow">Graph Summary</div>
        <strong>${escapeHtml(session?.name || "Untitled session")}</strong>
        <div class="nav-hint">${escapeHtml(session?.config?.target || "No target selected")}</div>
      </div>
    `;
    return;
  }

  el("graph-focus").innerHTML = `
    <div class="focus-block">
      <div class="eyebrow">Selected Node</div>
      <strong>${escapeHtml(selectedNode.label)}</strong>
      <div class="nav-hint">${escapeHtml(selectedNode.title || "Graph entity")}</div>
    </div>
    <div class="focus-block">
      <div class="eyebrow">Meaning</div>
      <strong>${escapeHtml(selectedNode.detail || "No extra detail is available for this node.")}</strong>
    </div>
    <div class="focus-block">
      <div class="eyebrow">Linked Entities</div>
      <strong>${escapeHtml(String(linkedNodes.length))} directly connected node${linkedNodes.length === 1 ? "" : "s"}</strong>
      <ul class="focus-list">
        ${(linkedNodes.length > 0 ? linkedNodes : [{ label: "No direct neighbors", type: "idle" }]).map((node) => `<li>${escapeHtml(node.label)}${node.type ? ` (${escapeHtml(node.type)})` : ""}</li>`).join("")}
      </ul>
    </div>
    <div class="focus-block">
      <div class="eyebrow">Recommended Next Move</div>
      <strong>${escapeHtml((selectedNode.recommendations || [])[0] || "Use the linked reports and event stream to continue inspection.")}</strong>
    </div>
    <div class="focus-block">
      <div class="eyebrow">Session Context</div>
      <strong>${escapeHtml(`${summary.subdomains || 0} hosts, ${summary.open_ports || 0} services, ${summary.findings || 0} findings are currently represented in this session.`)}</strong>
    </div>
  `;
}

function renderGraph(session) {
  const model = extractGraphModel(session);
  const selection = buildGraphSelection(model, state.selectedGraphNode || "target");
  const edgeMarkup = model.edges.map((edge) => {
    const from = model.nodes.find((node) => node.id === edge.from);
    const to = model.nodes.find((node) => node.id === edge.to);
    if (!from || !to) return "";
    const edgeConnected = edge.from === selection.selectedNode?.id || edge.to === selection.selectedNode?.id;
    const edgeClass = edgeConnected ? "graph-edge connected" : (selection.selectedNode ? "graph-edge dimmed" : "graph-edge");
    return `<line class="${edgeClass}" x1="${from.x}" y1="${from.y}" x2="${to.x}" y2="${to.y}"></line>`;
  }).join("");

  const nodeMarkup = model.nodes.map((node) => `
    <g class="graph-node ${escapeHtml(node.type)} ${node.id === selection.selectedNode?.id ? "active" : ""} ${selection.connectedIds.has(node.id) ? "connected" : "dimmed"}" data-node-id="${escapeHtml(node.id)}">
      <circle cx="${node.x}" cy="${node.y}" r="${node.type === "target" ? 34 : 28}"></circle>
      <text x="${node.x}" y="${node.y + 4}" text-anchor="middle">${escapeHtml(node.label.slice(0, 18))}</text>
    </g>
  `).join("");

  el("graph-canvas").innerHTML = `
    <svg viewBox="0 0 920 560" aria-label="Connected scan entities">
      ${edgeMarkup}
      ${nodeMarkup}
    </svg>
  `;
  Array.from(el("graph-canvas").querySelectorAll("[data-node-id]")).forEach((node) => {
    node.addEventListener("click", () => {
      state.selectedGraphNode = node.getAttribute("data-node-id");
      renderGraph(session);
    });
  });
  renderGraphFocus(session, model, selection);
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
  el("hero-title").textContent = session?.running ? "Live session in progress" : "A cleaner recon workspace";
  el("hero-copy").textContent = session?.running ? "The session is active. Use the activity drawer for live status while the dashboard, graph, reports, and docs stay available." : "This shell uses a lighter control-plane pattern with module tabs, charts, and a connected graph view so inspection stays practical.";
  const runDisabled = !target || session?.running;
  el("run-session").disabled = runDisabled;
  el("save-session").disabled = session?.running === true;
  el("stop-session").disabled = session?.running !== true;
  el("clone-session").disabled = !state.current;
  el("delete-session").disabled = !state.current || session?.running === true;
}

function updateSummary(session) {
  const summary = summaryFor(session);
  el("sum-subdomains").textContent = summary.subdomains || 0;
  el("sum-ips").textContent = summary.ips || 0;
  el("sum-ports").textContent = summary.open_ports || 0;
  el("sum-web").textContent = summary.http_responses || 0;
  el("sum-findings").textContent = summary.findings || 0;
  renderDonutChart(session || {});
  renderTrendChart(session || {});
  renderBarChart(summary);
  renderSnapshot(session || {});
  renderOverview(session || {});
  renderControlPlane(session || {});
  renderReports(session || {});
  renderActivity(session || {});
  renderDetails(session || {});
  renderTopAssets(session || {});
  renderFindings(session || {});
  renderGraph(session || {});
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
  fillForm(state.currentSession || { config: defaults, payload: { store: {} } });
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

async function cloneCurrentSession() {
  if (!state.current) {
    window.alert("Select or save a session first.");
    return;
  }
  const response = await api(`/api/session/clone?id=${encodeURIComponent(state.current)}`, { method: "POST" });
  if (!response.session) {
    window.alert("This session could not be duplicated.");
    return;
  }
  await refreshSessions(response.session.id, { reloadCurrent: false });
  await loadSession(response.session.id, false);
  switchView("sessions");
}

async function deleteCurrentSession() {
  if (!state.current) return;
  const sessionName = state.currentSession?.name || "this session";
  if (!window.confirm(`Delete ${sessionName}? This removes the saved web-session draft but leaves generated reports on disk.`)) return;
  const response = await fetch(`/api/session?id=${encodeURIComponent(state.current)}`, { method: "DELETE" });
  if (!response.ok) {
    window.alert("This session could not be deleted.");
    return;
  }
  const fallbackId = state.sessions.find((session) => session.id !== state.current)?.id || null;
  state.current = null;
  state.currentSession = null;
  await refreshSessions(fallbackId, { reloadCurrent: false });
  if (fallbackId) {
    await loadSession(fallbackId, false);
  } else {
    createSession();
  }
}

async function stopCurrentSession() {
  if (!state.current) return;
  const response = await api(`/api/session/stop?id=${encodeURIComponent(state.current)}`, { method: "POST" });
  if (!response.ok) {
    window.alert("This session is not currently running.");
    return;
  }
  await loadSession(state.current, false);
  setDrawerOpen(true);
}

function applyModePreset(mode) {
  el("mode").value = mode;
  syncModeControls();
  markDirty();
}

function createSession() {
  state.current = null;
  state.currentSession = { name: "Untitled session", config: defaults, summary: {}, payload: { store: {} } };
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
  renderExtensionCatalog("plugins");
  renderExtensionCatalog("filters");
  renderExtensionResolution(formData());
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
  el("mode").addEventListener("change", syncModeControls);

  el("theme-toggle").addEventListener("click", toggleTheme);
  el("clone-session").addEventListener("click", () => cloneCurrentSession());
  el("delete-session").addEventListener("click", () => deleteCurrentSession());
  el("stop-session").addEventListener("click", () => stopCurrentSession());
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
  document.querySelectorAll("[data-mode-preset]").forEach((node) => {
    node.addEventListener("click", () => applyModePreset(node.getAttribute("data-mode-preset") || "scan"));
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
  applyTheme(resolveTheme());
  const data = await api("/api/bootstrap");
  state.bootstrap = data.server || {};
  state.capabilities = data.capabilities || {};
  state.about = data.about || "";
  state.docs = Array.isArray(data.docs) ? data.docs : [];
  state.firstRun = data.first_run === true;
  state.firstRunGuide = Array.isArray(data.first_run_guide) ? data.first_run_guide : [];
  state.sessions = Array.isArray(data.sessions) ? data.sessions : [];
  applyCapabilities(state.capabilities);

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
