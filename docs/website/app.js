const DocsData = (() => {
  const pages = {
    "index.html": { title: "Overview", short: "Home" },
    "getting-started.html": { title: "Getting Started", short: "Start" },
    "workflow.html": { title: "Workflow", short: "Flow" },
    "cli-reference.html": { title: "CLI Reference", short: "CLI" },
    "modes.html": { title: "Modes & Examples", short: "Modes" },
    "reporting.html": { title: "Reporting & Config", short: "Reports" },
    "project.html": { title: "Project", short: "Project" }
  };

  const entries = [
    { id: "home", title: "Overview", page: "index.html", hint: "Landing page, capabilities, release status, and site map.", group: "Start Here" },
    { id: "install", title: "Installation", page: "getting-started.html", hint: "Bundler setup, installers, aliases, and prerequisites.", group: "Start Here" },
    { id: "quickstart", title: "Quick Start", page: "getting-started.html", hint: "First safe run, common commands, and early operator flow.", group: "Start Here" },
    { id: "how", title: "How It Works", page: "workflow.html", hint: "Mental model for the framework and how stages feed each other.", group: "Pipeline" },
    { id: "pipeline", title: "Scan Pipeline", page: "workflow.html", hint: "Stage-by-stage execution order and expected outputs.", group: "Pipeline" },
    { id: "passive", title: "Passive Sources", page: "workflow.html", hint: "External passive sources, their role, and what they return.", group: "Pipeline" },
    { id: "modules", title: "Core Modules", page: "workflow.html", hint: "High-level framework ownership and module boundaries.", group: "Pipeline" },
    { id: "commands", title: "Commands", page: "cli-reference.html", hint: "Primary command surfaces for daily usage.", group: "Operators" },
    { id: "flags", title: "Global Flags", page: "cli-reference.html", hint: "Cross-command switches, throttling, and output controls.", group: "Operators" },
    { id: "syntax", title: "Syntax Guide", page: "cli-reference.html", hint: "Command grammar, examples, and operator shorthand.", group: "Operators" },
    { id: "console", title: "Console Mode", page: "modes.html", hint: "Interactive shell with built-in docs and guided helpers.", group: "Modes" },
    { id: "web", title: "Web Session Mode", page: "modes.html", hint: "Browser control panel, saved sessions, and UI behavior.", group: "Modes" },
    { id: "wizard", title: "Wizard Mode", page: "modes.html", hint: "Preset-led operator onboarding and guided execution.", group: "Modes" },
    { id: "lab", title: "Lab Mode", page: "modes.html", hint: "Safe local practice targets before touching real systems.", group: "Modes" },
    { id: "examples", title: "Usage Examples", page: "modes.html", hint: "Common workflows and realistic command patterns.", group: "Modes" },
    { id: "outputs", title: "Output Formats", page: "reporting.html", hint: "CLI, TXT, HTML, JSON, and what each is good for.", group: "Reports" },
    { id: "config", title: "Configuration", page: "reporting.html", hint: "Defaults, overrides, and operator config behavior.", group: "Reports" },
    { id: "storage", title: "Files & Storage", page: "reporting.html", hint: "Where reports, memory, sessions, and lab data live.", group: "Reports" },
    { id: "testing", title: "Testing", page: "reporting.html", hint: "Rake verification, smoke tests, and release checks.", group: "Reports" },
    { id: "author", title: "Project & License", page: "project.html", hint: "Author, repository, license, and publishing context.", group: "Project" }
  ];

  const groups = ["Start Here", "Pipeline", "Operators", "Modes", "Reports", "Project"];

  return { pages, entries, groups };
})();

const DocsState = {
  currentPage: document.body.dataset.page || "index.html",
  currentSection: document.body.dataset.defaultSection || "home",
  navOpen: false
};

const DocsElements = {
  body: document.body,
  sidebar: document.getElementById("sidebar"),
  sidebarNav: document.getElementById("sidebar-nav"),
  sidebarBackdrop: document.getElementById("sidebar-backdrop"),
  menuToggle: document.getElementById("menu-toggle"),
  searchInput: document.getElementById("docs-search-input"),
  searchResults: document.getElementById("docs-search-results"),
  homeHeroLogo: document.getElementById("home-hero-logo"),
  homeHeroEgg: document.getElementById("home-hero-egg"),
  title: document.querySelector("title")
};

const DocsHelpers = (() => {
  function hrefFor(entry) {
    return `${entry.page}#${entry.id}`;
  }

  function normalizePage(pathname) {
    const page = pathname.split("/").pop();
    return page && page.length > 0 ? page : "index.html";
  }

  function findEntry(id) {
    return DocsData.entries.find((entry) => entry.id === id);
  }

  function currentHashId() {
    return window.location.hash.replace(/^#/, "");
  }

  function currentEntry() {
    const hashed = currentHashId();
    if (hashed && findEntry(hashed)) {
      return findEntry(hashed);
    }

    return findEntry(DocsState.currentSection);
  }

  function goToEntry(entry) {
    if (!entry) {
      return;
    }

    const targetHref = hrefFor(entry);
    const samePage = normalizePage(window.location.pathname) === entry.page;

    if (samePage) {
      history.replaceState(null, "", `#${entry.id}`);
      syncCurrentSection();
      scrollToSection(entry.id);
      Sidebar.syncActive();
    } else {
      window.location.href = targetHref;
    }
  }

  function scrollToSection(id) {
    const target = document.getElementById(id);
    if (!target) {
      return;
    }

    const topbarHeight = document.getElementById("topbar")?.offsetHeight || 0;
    const top = target.getBoundingClientRect().top + window.scrollY - topbarHeight - 24;
    window.scrollTo({ top, behavior: "smooth" });
  }

  function syncCurrentSection() {
    const hashed = currentHashId();
    DocsState.currentSection = findEntry(hashed) ? hashed : (document.body.dataset.defaultSection || "home");
    const entry = currentEntry();
    const page = DocsData.pages[DocsState.currentPage];
    const pageTitle = page ? page.title : "ASRFacet-Rb";
    document.title = entry && entry.id !== document.body.dataset.defaultSection
      ? `${entry.title} | ${pageTitle} | ASRFacet-Rb`
      : `${pageTitle} | ASRFacet-Rb`;
  }

  return {
    hrefFor,
    findEntry,
    currentEntry,
    currentHashId,
    goToEntry,
    scrollToSection,
    syncCurrentSection
  };
})();

const Sidebar = (() => {
  function renderGroup(group) {
    const groupEntries = DocsData.entries.filter((entry) => entry.group === group);
    if (groupEntries.length === 0) {
      return "";
    }

    const items = groupEntries.map((entry) => {
      const pageLabel = DocsData.pages[entry.page]?.short || "Docs";
      return `
        <a class="nav-item" data-section-id="${entry.id}" data-page="${entry.page}" href="${DocsHelpers.hrefFor(entry)}">
          <span class="nav-item-main">
            <span class="nav-label">${entry.title}</span>
            <span class="nav-hint">${entry.hint}</span>
          </span>
          <span class="nav-page-tag">${pageLabel}</span>
        </a>
      `;
    }).join("");

    return `
      <section class="nav-group">
        <div class="nav-section-title">${group}</div>
        <div class="nav-list">${items}</div>
      </section>
    `;
  }

  function render() {
    DocsElements.sidebarNav.innerHTML = DocsData.groups.map(renderGroup).join("");

    DocsElements.sidebarNav.querySelectorAll(".nav-item").forEach((item) => {
      item.addEventListener("click", (event) => {
        event.preventDefault();
        const entry = DocsHelpers.findEntry(item.dataset.sectionId);
        setOpen(false);
        DocsHelpers.goToEntry(entry);
      });
    });

    syncActive();
  }

  function syncActive() {
    const active = DocsHelpers.currentEntry();

    DocsElements.sidebarNav.querySelectorAll(".nav-item").forEach((item) => {
      const isActive =
        active &&
        item.dataset.sectionId === active.id &&
        item.dataset.page === active.page;

      item.classList.toggle("active", Boolean(isActive));
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

const Search = (() => {
  function renderResults(query = "") {
    const needle = query.trim().toLowerCase();
    const results = DocsData.entries.filter((entry) => {
      if (needle.length === 0) {
        return DocsData.pages[entry.page]?.title === DocsData.pages[DocsState.currentPage]?.title;
      }

      return [
        entry.title,
        entry.hint,
        entry.group,
        DocsData.pages[entry.page]?.title || ""
      ].some((value) => value.toLowerCase().includes(needle));
    });

    if (results.length === 0) {
      DocsElements.searchResults.innerHTML = '<div class="command-result-empty">No matching docs pages. Try install, pipeline, console, reports, or testing.</div>';
      return;
    }

    DocsElements.searchResults.innerHTML = results.map((entry) => `
      <button type="button" class="command-result" data-section-id="${entry.id}">
        <span class="command-result-title">${entry.title}</span>
        <span class="command-result-meta">${DocsData.pages[entry.page]?.title || "Docs"}</span>
        <span class="command-result-desc">${entry.hint}</span>
      </button>
    `).join("");

    DocsElements.searchResults.querySelectorAll(".command-result").forEach((button) => {
      button.addEventListener("click", () => {
        const entry = DocsHelpers.findEntry(button.dataset.sectionId);
        Sidebar.setOpen(false);
        DocsHelpers.goToEntry(entry);
      });
    });
  }

  function bind() {
    DocsElements.searchInput?.addEventListener("input", (event) => {
      renderResults(event.target.value);
    });
    DocsElements.searchInput?.addEventListener("focus", () => {
      renderResults(DocsElements.searchInput.value);
    });
  }

  return { bind, renderResults };
})();

const App = (() => {
  function bindHomeEasterEgg() {
    const logo = DocsElements.homeHeroLogo;
    if (!logo) {
      return;
    }

    const egg = DocsElements.homeHeroEgg;
    let eggTimer = null;

    const triggerSpin = () => {
      logo.classList.remove("egg-spin");
      void logo.offsetWidth;
      logo.classList.add("egg-spin");

      if (!egg) {
        return;
      }

      egg.classList.remove("show");
      void egg.offsetWidth;
      egg.classList.add("show");

      if (eggTimer) {
        window.clearTimeout(eggTimer);
      }

      eggTimer = window.setTimeout(() => {
        egg.classList.remove("show");
      }, 1500);
    };

    logo.addEventListener("click", triggerSpin);
    logo.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        triggerSpin();
      }
    });

    logo.addEventListener("animationend", (event) => {
      if (event.animationName === "hero-spin-once") {
        logo.classList.remove("egg-spin");
      }
    });
  }

  function bindGlobalEvents() {
    DocsElements.menuToggle?.addEventListener("click", Sidebar.toggle);
    DocsElements.sidebarBackdrop?.addEventListener("click", () => Sidebar.setOpen(false));

    window.addEventListener("hashchange", () => {
      DocsHelpers.syncCurrentSection();
      Sidebar.syncActive();
      if (DocsHelpers.currentHashId()) {
        DocsHelpers.scrollToSection(DocsHelpers.currentHashId());
      }
    });

    document.addEventListener("keydown", (event) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        DocsElements.searchInput?.focus();
        return;
      }

      if (event.key === "/") {
        const target = event.target;
        const editable =
          target instanceof HTMLElement &&
          (target.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName));

        if (!editable) {
          event.preventDefault();
          DocsElements.searchInput?.focus();
        }
        return;
      }

      if (event.key === "Escape") {
        if (DocsState.navOpen) {
          Sidebar.setOpen(false);
        } else if (DocsElements.searchInput && document.activeElement === DocsElements.searchInput) {
          DocsElements.searchInput.blur();
        }
      }
    });
  }

  function init() {
    DocsHelpers.syncCurrentSection();
    Sidebar.render();
    Search.bind();
    Search.renderResults("");
    bindHomeEasterEgg();
    bindGlobalEvents();

    if (DocsHelpers.currentHashId()) {
      setTimeout(() => DocsHelpers.scrollToSection(DocsHelpers.currentHashId()), 0);
    }
  }

  return { init };
})();

window.show = (id) => DocsHelpers.goToEntry(DocsHelpers.findEntry(id));
window.toggleNav = () => Sidebar.toggle();

App.init();
