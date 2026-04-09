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
