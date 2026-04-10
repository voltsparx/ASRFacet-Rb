const App = (() => {
  function enhanceChrome() {
    const topbarLinks = document.getElementById("topbar-links");
    if (topbarLinks && !topbarLinks.querySelector('[data-site-link="development"]')) {
      const developmentLink = document.createElement("a");
      developmentLink.href = "development.html#development-home";
      developmentLink.dataset.siteLink = "development";
      developmentLink.textContent = "Development";
      topbarLinks.insertBefore(developmentLink, topbarLinks.firstElementChild || null);
    }

    const mobileShortcuts = document.getElementById("mobile-shortcuts");
    if (mobileShortcuts && !mobileShortcuts.querySelector('[data-site-link="development"]')) {
      const developmentLink = document.createElement("a");
      developmentLink.href = "development.html#development-home";
      developmentLink.dataset.siteLink = "development";
      developmentLink.textContent = "Development";
      mobileShortcuts.insertBefore(developmentLink, mobileShortcuts.children[1] || null);
    }
  }

  function trimEmptyVisualCards() {
    const cardSelectors = [
      ".ov-card",
      ".install-card",
      ".cmd-card",
      ".src-card",
      ".fmt-card",
      ".wiz-card",
      ".stat-item"
    ];

    cardSelectors.forEach((selector) => {
      document.querySelectorAll(selector).forEach((card) => {
        const text = (card.textContent || "").replace(/\s+/g, " ").trim();
        if (!text) {
          card.remove();
        }
      });
    });
  }

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
        if (typeof RawPopup !== "undefined" && RawPopup.isOpen()) {
          RawPopup.close();
          return;
        }

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
    enhanceChrome();
    trimEmptyVisualCards();
    DocsHelpers.syncCurrentSection();
    Sidebar.render();
    EasterEgg.bind();
    Search.bind();
    WorkflowVisual.bind();
    RawPopup.bind();
    void DevelopmentFeed.bind();
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
