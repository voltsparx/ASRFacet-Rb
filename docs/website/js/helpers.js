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

