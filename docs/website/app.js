const DocsData = (() => {
  const pages = {
    "index.html": { title: "Overview", short: "Home" },
    "getting-started.html": { title: "Getting Started", short: "Start" },
    "download.html": { title: "Download Center", short: "DL" },
    "workflow.html": { title: "Workflow", short: "Flow" },
    "cli-reference.html": { title: "CLI Reference", short: "CLI" },
    "modes.html": { title: "Modes & Examples", short: "Modes" },
    "reporting.html": { title: "Reporting & Config", short: "Reports" },
    "project.html": { title: "Project", short: "Project" }
  };

  const entries = [
    { id: "home", title: "Overview", page: "index.html", hint: "Landing page, capabilities, release status, and site map.", group: "Start Here" },
    { id: "install", title: "Installation", page: "getting-started.html", hint: "Bundler setup, installers, aliases, and prerequisites.", group: "Start Here" },
    { id: "web-installers", title: "Website Installers", page: "download.html", hint: "Direct downloadable installers for Linux, macOS, and Windows.", group: "Start Here" },
    { id: "quickstart", title: "Quick Start", page: "getting-started.html", hint: "First safe run, common commands, and early operator flow.", group: "Start Here" },
    { id: "download-home", title: "Download Hub", page: "download.html", hint: "Central page for direct installer downloads and safe usage.", group: "Downloads" },
    { id: "download-scripts", title: "Installer Scripts", page: "download.html", hint: "Download links for Linux, macOS, and Windows installer scripts.", group: "Downloads" },
    { id: "download-usage", title: "Installer Usage", page: "download.html", hint: "Install, test, update, and uninstall lifecycle commands.", group: "Downloads" },
    { id: "download-paths", title: "Install Paths", page: "download.html", hint: "Where the framework and persistent data are stored.", group: "Downloads" },
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

  const groups = ["Start Here", "Downloads", "Pipeline", "Operators", "Modes", "Reports", "Project"];

  return { pages, entries, groups };
})();

const DocsState = {
  currentPage: document.body.dataset.page || "index.html",
  currentSection: document.body.dataset.defaultSection || "home",
  navOpen: false,
  navGroupFilter: "All",
  searchOpen: false
};

const DocsElements = {
  body: document.body,
  topbarLogo: document.getElementById("topbar-logo"),
  topbarName: document.getElementById("topbar-name"),
  topbarVersion: document.getElementById("topbar-version"),
  topbarSearch: document.getElementById("topbar-search"),
  sidebar: document.getElementById("sidebar"),
  sidebarTabs: document.getElementById("sidebar-tabs"),
  sidebarNav: document.getElementById("sidebar-nav"),
  sidebarBackdrop: document.getElementById("sidebar-backdrop"),
  menuToggle: document.getElementById("menu-toggle"),
  searchInput: document.getElementById("docs-search-input"),
  searchResults: document.getElementById("docs-search-results"),
  homeHeroLogo: document.getElementById("home-hero-logo"),
  homeHeroEgg: document.getElementById("home-hero-egg"),
  siteFooter: document.getElementById("site-footer"),
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
    renderTabs();
    const groups = DocsState.navGroupFilter === "All" ? DocsData.groups : [DocsState.navGroupFilter];
    DocsElements.sidebarNav.innerHTML = groups.map(renderGroup).join("");

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

  function renderTabs() {
    if (!DocsElements.sidebarTabs) {
      return;
    }

    const tabs = ["All", ...DocsData.groups];
    DocsElements.sidebarTabs.innerHTML = tabs.map((group) => `
      <button type="button" class="sidebar-tab" data-group="${group}">${group}</button>
    `).join("");

    DocsElements.sidebarTabs.querySelectorAll(".sidebar-tab").forEach((button) => {
      button.addEventListener("click", () => {
        DocsState.navGroupFilter = button.dataset.group || "All";
        render();
      });
    });

    syncTabs();
  }

  function syncTabs() {
    if (!DocsElements.sidebarTabs) {
      return;
    }

    DocsElements.sidebarTabs.querySelectorAll(".sidebar-tab").forEach((button) => {
      button.classList.toggle("active", button.dataset.group === DocsState.navGroupFilter);
    });
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

const EasterEgg = (() => {
  const toastId = "egg-toast";
  const secretQueries = {
    asrfrb: () => {
      showToast("Alias recognized: asrfrb");
      spawnConfetti(20);
    },
    reconparty: () => {
      showToast("Recon party mode activated");
      spawnConfetti(26);
    },
    upupdowndownleftrightleftrightba: () => {
      activateOverdrive({ message: "Konami accepted: recon overdrive", duration: 14000, confettiCount: 30 });
    },
    overdrivesync: () => {
      activateOverdrive({
        message: "over drive sync - ribbons fall",
        duration: 14000,
        confettiCount: 30
      });
    }
  };

  let logoTapCount = 0;
  let logoTapTimer = null;
  let nameTapCount = 0;
  let nameTapTimer = null;
  let searchTapCount = 0;
  let searchTapTimer = null;
  let footerTapCount = 0;
  let footerTapTimer = null;
  let longPressTimer = null;
  let menuLongPressTimer = null;
  let overdriveTimer = null;
  let ghostModeTimer = null;
  let signalLockTimer = null;
  let toastTimer = null;
  let lastSecretQuery = "";

  function ensureToast() {
    let toast = document.getElementById(toastId);
    if (toast) {
      return toast;
    }

    toast = document.createElement("div");
    toast.id = toastId;
    toast.className = "egg-toast";
    toast.setAttribute("aria-live", "polite");
    DocsElements.body.appendChild(toast);
    return toast;
  }

  function showToast(message) {
    const toast = ensureToast();
    toast.textContent = message;
    toast.classList.add("show");

    if (toastTimer) {
      window.clearTimeout(toastTimer);
    }

    toastTimer = window.setTimeout(() => {
      toast.classList.remove("show");
    }, 2200);
  }

  function spawnConfetti(options = {}) {
    const count = Number.isFinite(options) ? options : (Number.isFinite(options.count) ? options.count : 20);
    const layer = document.createElement("div");
    layer.className = "egg-confetti-layer";
    DocsElements.body.appendChild(layer);

    const colors = ["#ff5a5f", "#ffd166", "#7ee787", "#79c0ff", "#c297ff"];
    const total = Math.max(8, Math.min(count, 48));

    for (let i = 0; i < total; i += 1) {
      const bit = document.createElement("span");
      bit.className = "egg-confetti";
      bit.style.left = `${Math.random() * 100}%`;
      bit.style.background = colors[i % colors.length];
      bit.style.setProperty("--egg-drift", `${(Math.random() * 180) - 90}px`);
      bit.style.animationDuration = `${2.2 + (Math.random() * 1.8)}s`;
      bit.style.animationDelay = `${Math.random() * 0.25}s`;
      layer.appendChild(bit);
    }

    window.setTimeout(() => {
      layer.remove();
    }, 3200);
  }

  function activateOverdrive(options = {}) {
    const message = options.message || "Recon overdrive enabled for 12 seconds";
    const duration = Number.isFinite(options.duration) ? options.duration : 12000;
    const confettiCount = Number.isFinite(options.confettiCount) ? options.confettiCount : 24;

    DocsElements.body.classList.add("egg-overdrive");
    showToast(message);
    spawnConfetti(confettiCount);

    if (overdriveTimer) {
      window.clearTimeout(overdriveTimer);
    }
    overdriveTimer = window.setTimeout(() => {
      DocsElements.body.classList.remove("egg-overdrive");
    }, duration);
  }

  function toggleBlueprintMode() {
    const enabled = DocsElements.body.classList.toggle("egg-blueprint");
    showToast(enabled ? "Blueprint mode enabled" : "Blueprint mode disabled");
  }

  function activateSignalLock(duration = 4200) {
    DocsElements.body.classList.add("egg-signal-lock");
    showToast("signal lock acquired");
    spawnConfetti(14);

    if (signalLockTimer) {
      window.clearTimeout(signalLockTimer);
    }
    signalLockTimer = window.setTimeout(() => {
      DocsElements.body.classList.remove("egg-signal-lock");
    }, duration);
  }

  function activateGhostMode(duration = 10000) {
    DocsElements.body.classList.add("egg-ghost-mode");
    showToast("ghost mode active");

    if (ghostModeTimer) {
      window.clearTimeout(ghostModeTimer);
    }
    ghostModeTimer = window.setTimeout(() => {
      DocsElements.body.classList.remove("egg-ghost-mode");
    }, duration);
  }

  function toggleCleanScreen() {
    const enabled = DocsElements.body.classList.toggle("egg-clean-screen");
    showToast(enabled ? "clean screen enabled" : "clean screen disabled");
  }

  function bindLogoTapCombo() {
    if (!DocsElements.topbarLogo) {
      return;
    }

    DocsElements.topbarLogo.addEventListener("click", () => {
      logoTapCount += 1;
      if (logoTapTimer) {
        window.clearTimeout(logoTapTimer);
      }

      logoTapTimer = window.setTimeout(() => {
        logoTapCount = 0;
      }, 1800);

      if (logoTapCount >= 5) {
        logoTapCount = 0;
        activateOverdrive({ message: "Topbar overdrive unlocked", duration: 9000, confettiCount: 20 });
      }
    });
  }

  function bindNameTapCombo() {
    if (!DocsElements.topbarName) {
      return;
    }

    DocsElements.topbarName.addEventListener("click", () => {
      nameTapCount += 1;
      if (nameTapTimer) {
        window.clearTimeout(nameTapTimer);
      }
      nameTapTimer = window.setTimeout(() => {
        nameTapCount = 0;
      }, 1600);

      if (nameTapCount >= 4) {
        nameTapCount = 0;
        activateSignalLock();
      }
    });
  }

  function bindVersionLongPress() {
    if (!DocsElements.topbarVersion) {
      return;
    }

    const startPress = (event) => {
      if (event.type === "mousedown" && event.button !== 0) {
        return;
      }
      if (longPressTimer) {
        window.clearTimeout(longPressTimer);
      }
      longPressTimer = window.setTimeout(() => {
        toggleBlueprintMode();
      }, 800);
    };

    const cancelPress = () => {
      if (longPressTimer) {
        window.clearTimeout(longPressTimer);
        longPressTimer = null;
      }
    };

    DocsElements.topbarVersion.addEventListener("mousedown", startPress);
    DocsElements.topbarVersion.addEventListener("mouseup", cancelPress);
    DocsElements.topbarVersion.addEventListener("mouseleave", cancelPress);
    DocsElements.topbarVersion.addEventListener("touchstart", startPress, { passive: true });
    DocsElements.topbarVersion.addEventListener("touchend", cancelPress);
    DocsElements.topbarVersion.addEventListener("touchcancel", cancelPress);
  }

  function bindMenuLongPress() {
    if (!DocsElements.menuToggle) {
      return;
    }

    const startPress = (event) => {
      if (event.type === "mousedown" && event.button !== 0) {
        return;
      }
      if (menuLongPressTimer) {
        window.clearTimeout(menuLongPressTimer);
      }
      menuLongPressTimer = window.setTimeout(() => {
        activateGhostMode();
      }, 900);
    };

    const cancelPress = () => {
      if (menuLongPressTimer) {
        window.clearTimeout(menuLongPressTimer);
        menuLongPressTimer = null;
      }
    };

    DocsElements.menuToggle.addEventListener("mousedown", startPress);
    DocsElements.menuToggle.addEventListener("mouseup", cancelPress);
    DocsElements.menuToggle.addEventListener("mouseleave", cancelPress);
    DocsElements.menuToggle.addEventListener("touchstart", startPress, { passive: true });
    DocsElements.menuToggle.addEventListener("touchend", cancelPress);
    DocsElements.menuToggle.addEventListener("touchcancel", cancelPress);
  }

  function bindSearchTapCombo() {
    if (!DocsElements.searchInput) {
      return;
    }

    DocsElements.searchInput.addEventListener("click", () => {
      searchTapCount += 1;
      if (searchTapTimer) {
        window.clearTimeout(searchTapTimer);
      }
      searchTapTimer = window.setTimeout(() => {
        searchTapCount = 0;
      }, 1500);

      if (searchTapCount >= 3) {
        searchTapCount = 0;
        toggleCleanScreen();
      }
    });
  }

  function bindFooterTapCombo() {
    if (!DocsElements.siteFooter) {
      return;
    }

    DocsElements.siteFooter.addEventListener("click", (event) => {
      const target = event.target;
      if (!(target instanceof HTMLElement)) {
        return;
      }

      const tapTarget = target.closest(".footer-col-title");
      if (!tapTarget) {
        return;
      }

      footerTapCount += 1;
      if (footerTapTimer) {
        window.clearTimeout(footerTapTimer);
      }
      footerTapTimer = window.setTimeout(() => {
        footerTapCount = 0;
      }, 1600);

      if (footerTapCount >= 3) {
        footerTapCount = 0;
        showToast("Hidden trace: keep calm, recon smart");
        spawnConfetti(16);
      }
    });
  }

  function onSearchInput(value = "") {
    const normalized = value.toLowerCase().replace(/[^a-z0-9]/g, "");
    const action = secretQueries[normalized];
    if (!action) {
      lastSecretQuery = "";
      return;
    }

    if (lastSecretQuery === normalized) {
      return;
    }

    lastSecretQuery = normalized;
    action();
  }

  function bind() {
    bindLogoTapCombo();
    bindNameTapCombo();
    bindVersionLongPress();
    bindMenuLongPress();
    bindSearchTapCombo();
    bindFooterTapCombo();
  }

  return { bind, onSearchInput, activateOverdrive, showToast, spawnConfetti };
})();

const Search = (() => {
  function setOpen(open) {
    DocsState.searchOpen = open;
    DocsElements.topbarSearch?.classList.toggle("open", open);
    if (!open && DocsElements.searchResults) {
      DocsElements.searchResults.innerHTML = "";
    }
  }

  function renderResults(query = "") {
    if (!DocsElements.searchResults) {
      return;
    }

    const needle = query.trim().toLowerCase();
    const results = DocsData.entries.filter((entry) => {
      if (needle.length === 0) {
        return true;
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
        setOpen(false);
        DocsElements.searchInput?.blur();
        DocsHelpers.goToEntry(entry);
      });
    });
  }

  function bind() {
    DocsElements.searchInput?.addEventListener("input", (event) => {
      EasterEgg.onSearchInput(event.target.value);
      setOpen(true);
      renderResults(event.target.value);
    });
    DocsElements.searchInput?.addEventListener("focus", () => {
      setOpen(true);
      renderResults(DocsElements.searchInput.value);
    });
    DocsElements.searchInput?.addEventListener("click", () => {
      setOpen(true);
      renderResults(DocsElements.searchInput.value);
    });
    document.addEventListener("click", (event) => {
      if (!DocsElements.topbarSearch) {
        return;
      }
      if (DocsElements.topbarSearch.contains(event.target)) {
        return;
      }
      setOpen(false);
    });
  }

  return { bind, renderResults, setOpen };
})();

const ContactPanel = (() => {
  let openContainer = null;

  function close(container) {
    if (!container) {
      return;
    }

    const toggle = container.querySelector(".topbar-contact-toggle");
    const popover = container.querySelector(".topbar-contact-popover");
    if (toggle) {
      toggle.setAttribute("aria-expanded", "false");
    }
    if (popover) {
      popover.classList.remove("is-open");
      popover.hidden = true;
      popover.setAttribute("aria-hidden", "true");
      popover.style.display = "none";
    }
    if (openContainer === container) {
      openContainer = null;
    }
  }

  function closeOpen() {
    if (openContainer) {
      close(openContainer);
    }
  }

  function bind() {
    const containers = document.querySelectorAll(".topbar-contact");
    if (containers.length === 0) {
      return;
    }

    containers.forEach((container) => {
      const toggle = container.querySelector(".topbar-contact-toggle");
      const popover = container.querySelector(".topbar-contact-popover");
      if (!toggle || !popover) {
        return;
      }

      popover.classList.remove("is-open");
      popover.hidden = true;
      popover.setAttribute("aria-hidden", "true");
      popover.style.display = "none";
      toggle.setAttribute("aria-expanded", "false");

      toggle.addEventListener("click", (event) => {
        event.preventDefault();
        const shouldOpen = !popover.classList.contains("is-open");
        closeOpen();
        popover.classList.toggle("is-open", shouldOpen);
        popover.hidden = !shouldOpen;
        popover.setAttribute("aria-hidden", shouldOpen ? "false" : "true");
        popover.style.display = shouldOpen ? "grid" : "none";
        toggle.setAttribute("aria-expanded", shouldOpen ? "true" : "false");
        openContainer = shouldOpen ? container : null;
      });
    });

    document.addEventListener("click", (event) => {
      if (!openContainer) {
        return;
      }
      if (openContainer.contains(event.target)) {
        return;
      }
      closeOpen();
    });
  }

  return { bind, closeOpen };
})();

const App = (() => {
  function bindHomeEasterEgg() {
    const logo = DocsElements.homeHeroLogo;
    if (!logo) {
      return;
    }

    const egg = DocsElements.homeHeroEgg;
    const defaultEggText = egg ? egg.textContent : "";
    let eggTimer = null;
    let tapCount = 0;
    let tapTimer = null;
    let syncTimer = null;

    const showEggText = (text, duration = 1500) => {
      if (!egg) {
        return;
      }

      egg.textContent = text;
      egg.classList.remove("show");
      void egg.offsetWidth;
      egg.classList.add("show");

      if (eggTimer) {
        window.clearTimeout(eggTimer);
      }

      eggTimer = window.setTimeout(() => {
        egg.classList.remove("show");
        if (defaultEggText) {
          egg.textContent = defaultEggText;
        }
      }, duration);
    };

    const triggerSpin = () => {
      logo.classList.remove("egg-spin");
      void logo.offsetWidth;
      logo.classList.add("egg-spin");

      showEggText(defaultEggText || "recon pulse synced", 1500);
    };

    const triggerOverdriveSync = () => {
      logo.classList.add("egg-overdrive-sync");
      showEggText("over drive sync - ribbons fall", 5200);
      EasterEgg.activateOverdrive({
        message: "over drive sync - ribbons fall",
        duration: 14000,
        confettiCount: 34
      });

      if (syncTimer) {
        window.clearTimeout(syncTimer);
      }
      syncTimer = window.setTimeout(() => {
        logo.classList.remove("egg-overdrive-sync");
      }, 6200);
    };

    const registerTap = () => {
      tapCount += 1;
      if (tapTimer) {
        window.clearTimeout(tapTimer);
      }
      tapTimer = window.setTimeout(() => {
        tapCount = 0;
      }, 2200);

      if (tapCount >= 7) {
        tapCount = 0;
        triggerOverdriveSync();
      }
    };

    const activateLogo = () => {
      triggerSpin();
      registerTap();
    };

    logo.addEventListener("click", activateLogo);
    logo.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        activateLogo();
      }
    });

    logo.addEventListener("animationend", (event) => {
      if (event.animationName === "hero-spin-once") {
        logo.classList.remove("egg-spin");
      }
    });
  }

  function bindGlobalEvents() {
    ContactPanel.bind();
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
        Search.setOpen(true);
        Search.renderResults(DocsElements.searchInput?.value || "");
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
          Search.setOpen(true);
          Search.renderResults(DocsElements.searchInput?.value || "");
        }
        return;
      }

      if (event.key === "Escape") {
        if (document.querySelector(".topbar-contact-popover:not([hidden])")) {
          ContactPanel.closeOpen();
          return;
        }
        if (DocsState.searchOpen) {
          Search.setOpen(false);
          DocsElements.searchInput?.blur();
          return;
        }
        if (DocsState.navOpen) {
          Sidebar.setOpen(false);
        } else if (DocsElements.searchInput && document.activeElement === DocsElements.searchInput) {
          DocsElements.searchInput.blur();
        }
      }
    });
  }

  function init() {
    DocsElements.body.classList.add("egg-clean-screen");
    DocsHelpers.syncCurrentSection();
    Sidebar.render();
    EasterEgg.bind();
    Search.bind();
    Search.setOpen(false);
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
