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

