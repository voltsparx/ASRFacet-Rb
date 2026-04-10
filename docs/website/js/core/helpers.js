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

  function githubApi(path = "") {
    return `https://api.github.com/repos/${DocsData.github.owner}/${DocsData.github.repo}${path}`;
  }

  function githubProfileApi() {
    return `https://api.github.com/users/${DocsData.github.owner}`;
  }

  function githubRaw(path = "") {
    return `https://raw.githubusercontent.com/${DocsData.github.owner}/${DocsData.github.repo}/${DocsData.github.branch}/${path}`;
  }

  function githubBlob(path = "") {
    return `https://github.com/${DocsData.github.owner}/${DocsData.github.repo}/blob/${DocsData.github.branch}/${path}`;
  }

  function escapeHtml(value = "") {
    return value
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function formatDate(value) {
    if (!value) {
      return "Unknown";
    }

    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) {
      return "Unknown";
    }

    return new Intl.DateTimeFormat("en", {
      year: "numeric",
      month: "short",
      day: "numeric"
    }).format(parsed);
  }

  function formatRelativeTime(value) {
    if (!value) {
      return "Unknown";
    }

    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) {
      return "Unknown";
    }

    const diffMs = Date.now() - parsed.getTime();
    const diffMinutes = Math.round(diffMs / 60000);

    if (diffMinutes < 60) {
      return `${Math.max(diffMinutes, 0)}m ago`;
    }

    const diffHours = Math.round(diffMinutes / 60);
    if (diffHours < 48) {
      return `${diffHours}h ago`;
    }

    const diffDays = Math.round(diffHours / 24);
    if (diffDays < 32) {
      return `${diffDays}d ago`;
    }

    const diffMonths = Math.round(diffDays / 30);
    return `${diffMonths}mo ago`;
  }

  function compactNumber(value) {
    return new Intl.NumberFormat("en", {
      notation: "compact",
      maximumFractionDigits: 1
    }).format(Number(value || 0));
  }

  return {
    hrefFor,
    findEntry,
    currentEntry,
    currentHashId,
    goToEntry,
    scrollToSection,
    syncCurrentSection,
    githubApi,
    githubProfileApi,
    githubRaw,
    githubBlob,
    escapeHtml,
    formatDate,
    formatRelativeTime,
    compactNumber
  };
})();

