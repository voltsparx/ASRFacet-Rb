const DocsData = (() => {
  const groups = [
    { title: "Start Here", ids: ["home", "install", "quickstart", "how"] },
    { title: "Pipeline", ids: ["pipeline", "passive", "modules"] },
    { title: "Operators", ids: ["commands", "flags", "syntax", "console", "web", "wizard"] },
    { title: "Practice", ids: ["lab", "examples", "testing"] },
    { title: "Reports", ids: ["outputs", "config", "storage"] },
    { title: "Project", ids: ["author"] }
  ];

  const hints = {
    home: "Overview, release state, and core capability cards.",
    install: "Bundler setup, installers, and man page entrypoints.",
    quickstart: "Fast commands for first runs and common workflows.",
    how: "Mental model for how the framework thinks and moves.",
    pipeline: "Stage-by-stage orchestration and execution order.",
    passive: "Passive sources, rate behavior, and enrichment flow.",
    commands: "Primary command surfaces for daily usage.",
    flags: "Global switches, tuning flags, and output controls.",
    syntax: "Command grammar and option patterns.",
    console: "Interactive operator shell and guided helpers.",
    web: "Local control panel mode with saved sessions.",
    wizard: "Preset-led onboarding for safer operator flow.",
    lab: "Safe local practice targets before real engagements.",
    modules: "Core framework subsystems and their roles.",
    outputs: "CLI, TXT, HTML, JSON, and report bundle behavior.",
    config: "Defaults, overrides, and operator configuration paths.",
    storage: "Where sessions, memory, reports, and state live.",
    examples: "Worked examples for common recon tasks.",
    testing: "Rake verification, smoke checks, and release validation.",
    author: "Author, license, contact, and repository links."
  };

  return { groups, hints };
})();

const DocsState = {
  sections: new Map(),
  orderedIds: [],
  activeId: null,
  navOpen: false,
  paletteOpen: false
};

const DocsElements = {
  body: document.body,
  sidebar: document.getElementById("sidebar"),
  sidebarNav: document.getElementById("sidebar-nav"),
  sidebarBackdrop: document.getElementById("sidebar-backdrop"),
  menuToggle: document.getElementById("menu-toggle"),
  palette: document.getElementById("command-palette"),
  paletteInput: document.getElementById("command-palette-input"),
  paletteResults: document.getElementById("command-palette-results"),
  paletteClose: document.getElementById("command-palette-close"),
  quickJumpTrigger: document.getElementById("quick-jump-trigger"),
  paletteTriggers: Array.from(document.querySelectorAll("[data-open-palette]")),
  title: document.querySelector("title")
};

const SectionRegistry = (() => {
  function titleFor(section) {
    const selectors = [".home-hero-title", ".page-title", ".footer-col-title"];
    for (const selector of selectors) {
      const match = section.querySelector(selector);
      if (match && match.textContent.trim()) {
        return match.textContent.trim();
      }
    }

    return section.id.replace(/^sec-/, "").replace(/-/g, " ");
  }

  function blurbFor(id) {
    return DocsData.hints[id] || "Reference material for this part of the framework.";
  }

  function collect() {
    const sections = Array.from(document.querySelectorAll(".page-section"));
    DocsState.sections.clear();
    DocsState.orderedIds = [];

    sections.forEach((section) => {
      const id = section.id.replace(/^sec-/, "");
      const title = titleFor(section);
      const entry = {
        id,
        title,
        blurb: blurbFor(id),
        element: section
      };

      DocsState.sections.set(id, entry);
      DocsState.orderedIds.push(id);
    });
  }

  function entriesForGroup(group) {
    return group.ids
      .map((id) => DocsState.sections.get(id))
      .filter(Boolean);
  }

  function allEntries() {
    return DocsState.orderedIds
      .map((id) => DocsState.sections.get(id))
      .filter(Boolean);
  }

  return { collect, entriesForGroup, allEntries };
})();

const Sidebar = (() => {
  function renderNavItem(entry) {
    const item = document.createElement("a");
    item.href = `#${entry.id}`;
    item.className = "nav-item";
    item.dataset.sectionId = entry.id;
    item.innerHTML = `
      <span class="nav-item-main">
        <span class="nav-label">${entry.title}</span>
        <span class="nav-hint">${entry.blurb}</span>
      </span>
    `;

    item.addEventListener("click", (event) => {
      event.preventDefault();
      Router.show(entry.id);
    });

    return item;
  }

  function renderGroup(group) {
    const items = SectionRegistry.entriesForGroup(group);
    if (items.length === 0) {
      return null;
    }

    const wrap = document.createElement("section");
    wrap.className = "nav-group";

    const heading = document.createElement("div");
    heading.className = "nav-section-title";
    heading.textContent = group.title;
    wrap.appendChild(heading);

    const list = document.createElement("div");
    list.className = "nav-list";
    items.forEach((entry) => list.appendChild(renderNavItem(entry)));
    wrap.appendChild(list);

    return wrap;
  }

  function render() {
    DocsElements.sidebarNav.innerHTML = "";
    DocsData.groups.forEach((group) => {
      const rendered = renderGroup(group);
      if (rendered) {
        DocsElements.sidebarNav.appendChild(rendered);
      }
    });
  }

  function syncActive(id) {
    document.querySelectorAll("#sidebar .nav-item").forEach((item) => {
      item.classList.toggle("active", item.dataset.sectionId === id);
    });
  }

  function setOpen(open) {
    DocsState.navOpen = open;
    DocsElements.sidebar.classList.toggle("open", open);
    DocsElements.body.classList.toggle("nav-open", open);
  }

  function toggle() {
    setOpen(!DocsState.navOpen);
  }

  return { render, syncActive, setOpen, toggle };
})();

const Palette = (() => {
  function resultsFor(query) {
    const needle = query.trim().toLowerCase();
    return SectionRegistry.allEntries().filter((entry) => {
      if (needle.length === 0) {
        return true;
      }

      return [entry.title, entry.id, entry.blurb].some((value) =>
        value.toLowerCase().includes(needle)
      );
    });
  }

  function renderResults(query = "") {
    const results = resultsFor(query);
    DocsElements.paletteResults.innerHTML = "";

    if (results.length === 0) {
      const empty = document.createElement("div");
      empty.className = "command-result-empty";
      empty.textContent = "No matching sections. Try a command name, feature, or topic.";
      DocsElements.paletteResults.appendChild(empty);
      return;
    }

    results.forEach((entry) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "command-result";
      button.dataset.sectionId = entry.id;
      button.innerHTML = `
        <span class="command-result-title">${entry.title}</span>
        <span class="command-result-meta">#${entry.id}</span>
        <span class="command-result-desc">${entry.blurb}</span>
      `;
      button.addEventListener("click", () => {
        close();
        Router.show(entry.id);
      });
      DocsElements.paletteResults.appendChild(button);
    });
  }

  function open() {
    DocsState.paletteOpen = true;
    DocsElements.palette.hidden = false;
    DocsElements.body.classList.add("palette-open");
    renderResults(DocsElements.paletteInput.value);
    window.requestAnimationFrame(() => DocsElements.paletteInput.focus());
  }

  function close() {
    DocsState.paletteOpen = false;
    DocsElements.palette.hidden = true;
    DocsElements.body.classList.remove("palette-open");
  }

  function bind() {
    DocsElements.paletteInput.addEventListener("input", (event) => {
      renderResults(event.target.value);
    });

    DocsElements.palette.addEventListener("click", (event) => {
      if (event.target === DocsElements.palette) {
        close();
      }
    });

    DocsElements.paletteClose.addEventListener("click", close);
    DocsElements.quickJumpTrigger.addEventListener("click", open);
    DocsElements.paletteTriggers.forEach((trigger) => {
      trigger.addEventListener("click", open);
    });
  }

  return { open, close, bind, renderResults };
})();

const Router = (() => {
  function normalizedId(id) {
    return DocsState.sections.has(id) ? id : "home";
  }

  function updateTitle(id) {
    const section = DocsState.sections.get(id);
    const base = "ASRFacet-Rb";
    document.title = section && id !== "home" ? `${section.title} | ${base}` : base;
  }

  function syncSection(id) {
    DocsState.sections.forEach((entry, key) => {
      entry.element.classList.toggle("active", key === id);
    });
  }

  function show(id, options = {}) {
    const { updateHash = true } = options;
    const targetId = normalizedId(id);

    DocsState.activeId = targetId;
    syncSection(targetId);
    Sidebar.syncActive(targetId);
    updateTitle(targetId);
    Sidebar.setOpen(false);

    if (updateHash && window.location.hash !== `#${targetId}`) {
      window.history.replaceState(null, "", `#${targetId}`);
    }

    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function syncFromHash() {
    const requested = window.location.hash.replace(/^#/, "");
    show(requested || "home", { updateHash: false });
  }

  return { show, syncFromHash };
})();

const App = (() => {
  function bindGlobalEvents() {
    DocsElements.menuToggle.addEventListener("click", Sidebar.toggle);
    DocsElements.sidebarBackdrop.addEventListener("click", () => Sidebar.setOpen(false));

    window.addEventListener("hashchange", Router.syncFromHash);

    document.addEventListener("keydown", (event) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        Palette.open();
        return;
      }

      if (event.key === "/" && !DocsState.paletteOpen) {
        const target = event.target;
        const editable =
          target instanceof HTMLElement &&
          (target.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName));

        if (!editable) {
          event.preventDefault();
          Palette.open();
        }
        return;
      }

      if (event.key === "Escape") {
        if (DocsState.paletteOpen) {
          Palette.close();
        } else if (DocsState.navOpen) {
          Sidebar.setOpen(false);
        }
      }
    });
  }

  function init() {
    SectionRegistry.collect();
    Sidebar.render();
    Palette.bind();
    Palette.renderResults("");
    bindGlobalEvents();
    Router.syncFromHash();
  }

  return { init };
})();

window.show = (id) => Router.show(id);
window.toggleNav = () => Sidebar.toggle();

App.init();
