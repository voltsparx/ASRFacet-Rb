const DevelopmentFeed = (() => {
  const selectors = {
    repoSummary: "#dev-repo-summary",
    chart: "#dev-commit-chart",
    releaseSummary: "#dev-release-summary",
    commits: "#dev-commits-list",
    commitsMore: "#dev-commits-more",
    contributors: "#dev-contributors-list",
    tags: "#dev-tags-list",
    links: "#dev-link-grid",
    pulse: "#dev-pulse",
    historyBackdrop: "#dev-history-backdrop",
    historyMeta: "#dev-history-meta",
    historyBody: "#dev-history-body",
    historyClose: "#dev-history-close"
  };

  let historyOpen = false;
  let historyLoaded = false;
  let historyLoading = false;
  let historyCache = [];

  function element(selector) {
    return document.querySelector(selector);
  }

  function hasPage() {
    return Boolean(element(selectors.repoSummary));
  }

  async function fetchJson(url) {
    const response = await fetch(url, {
      headers: { Accept: "application/vnd.github+json" }
    });

    if (!response.ok) {
      throw new Error(`GitHub returned ${response.status}`);
    }

    return response.json();
  }

  function setPulse(message, tone = "info") {
    const pulse = element(selectors.pulse);
    if (!pulse) {
      return;
    }

    pulse.className = `callout ${tone === "warn" ? "callout-warn" : "callout-info"}`;
    pulse.innerHTML = `
      <div class="callout-title">GitHub Pulse</div>
      ${DocsHelpers.escapeHtml(message)}
    `;
  }

  function renderRepoSummary(repo) {
    const node = element(selectors.repoSummary);
    if (!node) {
      return;
    }

    node.innerHTML = `
      <div class="dev-stat-grid">
        <div class="dev-stat"><span class="dev-stat-label">Stars</span><span class="dev-stat-value">${DocsHelpers.compactNumber(repo.stargazers_count)}</span></div>
        <div class="dev-stat"><span class="dev-stat-label">Forks</span><span class="dev-stat-value">${DocsHelpers.compactNumber(repo.forks_count)}</span></div>
        <div class="dev-stat"><span class="dev-stat-label">Open Issues</span><span class="dev-stat-value">${DocsHelpers.compactNumber(repo.open_issues_count)}</span></div>
        <div class="dev-stat"><span class="dev-stat-label">Watchers</span><span class="dev-stat-value">${DocsHelpers.compactNumber(repo.subscribers_count || repo.watchers_count)}</span></div>
      </div>
      <div class="dev-snapshot-grid">
        <div class="dev-snapshot-card">
          <span class="dev-snapshot-label">Default Branch</span>
          <strong class="dev-snapshot-value">${DocsHelpers.escapeHtml(repo.default_branch || "main")}</strong>
        </div>
        <div class="dev-snapshot-card">
          <span class="dev-snapshot-label">Last Push</span>
          <strong class="dev-snapshot-value">${DocsHelpers.formatDate(repo.pushed_at)}</strong>
          <span class="dev-snapshot-meta">${DocsHelpers.formatRelativeTime(repo.pushed_at)}</span>
        </div>
        <div class="dev-snapshot-card dev-snapshot-card-wide">
          <span class="dev-snapshot-label">Repository</span>
          <a class="dev-snapshot-link" href="${repo.html_url}" target="_blank" rel="noopener noreferrer">${DocsHelpers.escapeHtml(repo.full_name)}</a>
        </div>
      </div>
    `;
  }

  function buildCommitSeries(commits, days = 5) {
    const buckets = [];
    const counts = new Map();
    const today = new Date();

    for (let offset = days - 1; offset >= 0; offset -= 1) {
      const date = new Date(today);
      date.setHours(0, 0, 0, 0);
      date.setDate(date.getDate() - offset);
      const key = date.toISOString().slice(0, 10);
      buckets.push({
        key,
        label: date.toLocaleDateString(undefined, { weekday: "short" }),
        fullLabel: date.toLocaleDateString(undefined, { month: "short", day: "numeric" }),
        count: 0
      });
      counts.set(key, 0);
    }

    commits.forEach((commit) => {
      const date = commit.commit?.author?.date;
      if (!date) {
        return;
      }

      const key = new Date(date).toISOString().slice(0, 10);
      if (counts.has(key)) {
        counts.set(key, counts.get(key) + 1);
      }
    });

    return buckets.map((bucket) => ({
      ...bucket,
      count: counts.get(bucket.key) || 0
    }));
  }

  function chartPath(points) {
    return points.map((point, index) => `${index === 0 ? "M" : "L"} ${point.x} ${point.y}`).join(" ");
  }

  function renderCommitChart(commits) {
    const node = element(selectors.chart);
    if (!node) {
      return;
    }

    const series = buildCommitSeries(commits);
    const width = 760;
    const height = 300;
    const padding = { top: 26, right: 24, bottom: 56, left: 54 };
    const chartWidth = width - padding.left - padding.right;
    const chartHeight = height - padding.top - padding.bottom;
    const maxCount = Math.max(...series.map((item) => item.count), 1);
    const stepX = series.length > 1 ? chartWidth / (series.length - 1) : chartWidth;
    const points = series.map((item, index) => ({
      ...item,
      x: Number((padding.left + (stepX * index)).toFixed(2)),
      y: Number((padding.top + chartHeight - ((item.count / maxCount) * chartHeight)).toFixed(2))
    }));
    const line = chartPath(points);
    const area = `${line} L ${points[points.length - 1].x} ${padding.top + chartHeight} L ${points[0].x} ${padding.top + chartHeight} Z`;
    const peak = series.reduce((best, item) => (item.count > best.count ? item : best), series[0]);
    const total = series.reduce((sum, item) => sum + item.count, 0);
    const latestCommitAt = commits[0]?.commit?.author?.date;
    const gridSteps = Math.min(maxCount, 4);
    const gridValues = Array.from({ length: gridSteps + 1 }, (_, index) => {
      const value = Math.round((maxCount / Math.max(gridSteps, 1)) * index);
      return Math.min(value, maxCount);
    }).filter((value, index, array) => index === 0 || value !== array[index - 1]);

    node.innerHTML = `
      <div class="dev-chart-summary">
        <div class="dev-stat-grid">
          <div class="dev-stat"><span class="dev-stat-label">Last 5 Days</span><span class="dev-stat-value">${DocsHelpers.compactNumber(total)}</span></div>
          <div class="dev-stat"><span class="dev-stat-label">Peak Day</span><span class="dev-stat-value">${DocsHelpers.escapeHtml(peak.fullLabel)}</span></div>
        </div>
        <div class="dev-meta-list">
          <div><span>Peak commits</span><strong>${DocsHelpers.compactNumber(peak.count)}</strong></div>
          <div><span>Latest commit</span><strong>${latestCommitAt ? `${DocsHelpers.formatDate(latestCommitAt)} (${DocsHelpers.formatRelativeTime(latestCommitAt)})` : "No recent commit data"}</strong></div>
        </div>
      </div>
      <div class="dev-chart">
        <svg class="dev-chart-svg" viewBox="0 0 ${width} ${height}" role="img" aria-label="Commit activity graph for the last five days">
          <defs>
            <linearGradient id="dev-chart-fill" x1="0" x2="0" y1="0" y2="1">
              <stop offset="0%" stop-color="#ff5252" stop-opacity="0.45"></stop>
              <stop offset="100%" stop-color="#ff5252" stop-opacity="0.02"></stop>
            </linearGradient>
            <linearGradient id="dev-chart-line" x1="0" x2="1" y1="0" y2="0">
              <stop offset="0%" stop-color="#ff8a80"></stop>
              <stop offset="55%" stop-color="#ff5252"></stop>
              <stop offset="100%" stop-color="#ffc1b8"></stop>
            </linearGradient>
          </defs>
          ${gridValues.map((value) => {
            const y = Number((padding.top + chartHeight - ((value / maxCount) * chartHeight)).toFixed(2));
            return `
              <line class="dev-chart-grid" x1="${padding.left}" y1="${y}" x2="${width - padding.right}" y2="${y}"></line>
              <text class="dev-chart-axis dev-chart-axis-y" x="${padding.left - 14}" y="${y + 5}">${value}</text>
            `;
          }).join("")}
          <path class="dev-chart-fill" d="${area}"></path>
          <path class="dev-chart-line" d="${line}"></path>
          ${points.map((point) => `
            <g>
              <circle class="dev-chart-point-glow" cx="${point.x}" cy="${point.y}" r="7"></circle>
              <circle class="dev-chart-point" cx="${point.x}" cy="${point.y}" r="4.2"></circle>
              <text class="dev-chart-axis dev-chart-axis-x" x="${point.x}" y="${height - 18}" text-anchor="middle">${DocsHelpers.escapeHtml(point.label)}</text>
            </g>
          `).join("")}
        </svg>
        <div class="dev-chart-labels">
          ${series.map((item) => `
            <div class="dev-chart-label">
              <strong>${DocsHelpers.escapeHtml(item.fullLabel)}</strong>
              <span>${DocsHelpers.compactNumber(item.count)} commit${item.count === 1 ? "" : "s"}</span>
            </div>
          `).join("")}
        </div>
      </div>
    `;
  }

  function renderReleaseSummary(repo, release, tags) {
    const node = element(selectors.releaseSummary);
    if (!node) {
      return;
    }

    const latestRelease = release && !release.message ? (release.name || release.tag_name) : "No published release";
    const latestTag = Array.isArray(tags) && tags[0] ? tags[0].name : "No tags yet";

    node.innerHTML = `
      <div class="dev-pill-row">
        <span class="flag-pill">Default Branch: ${DocsHelpers.escapeHtml(repo.default_branch || "main")}</span>
        <span class="flag-pill">Latest Tag: ${DocsHelpers.escapeHtml(latestTag)}</span>
        <span class="flag-pill">Release: ${DocsHelpers.escapeHtml(latestRelease)}</span>
      </div>
      <div class="dev-meta-list">
        <div><span>CI</span><strong><a href="${DocsData.github.repoUrl}/actions/workflows/ci.yml" target="_blank" rel="noopener noreferrer">Workflow</a></strong></div>
        <div><span>Docs Website</span><strong><a href="${DocsData.github.repoUrl}/actions/workflows/pages.yml" target="_blank" rel="noopener noreferrer">Pages workflow</a></strong></div>
        <div><span>Latest movement</span><strong>${DocsHelpers.formatRelativeTime(repo.pushed_at)}</strong></div>
      </div>
    `;
  }

  function renderCommits(commits) {
    const node = element(selectors.commits);
    if (!node) {
      return;
    }

    node.innerHTML = commits.slice(0, 5).map((commit) => {
      const sha = (commit.sha || "").slice(0, 7);
      const message = (commit.commit?.message || "Commit").split("\n")[0];
      const author = commit.commit?.author?.name || commit.author?.login || "Unknown";
      const date = commit.commit?.author?.date;

      return `
        <a class="dev-list-item" href="${commit.html_url}" target="_blank" rel="noopener noreferrer">
          <div class="dev-list-title">${DocsHelpers.escapeHtml(message)}</div>
          <div class="dev-list-meta">${DocsHelpers.escapeHtml(sha)} | ${DocsHelpers.escapeHtml(author)} | ${DocsHelpers.formatDate(date)} (${DocsHelpers.formatRelativeTime(date)})</div>
        </a>
      `;
    }).join("");
  }

  function renderHistory(commits) {
    const node = element(selectors.historyBody);
    const meta = element(selectors.historyMeta);
    if (!node || !meta) {
      return;
    }

    if (!Array.isArray(commits) || commits.length === 0) {
      meta.textContent = "No commit history could be fetched from GitHub right now.";
      node.innerHTML = '<div class="callout callout-warn"><div class="callout-title">History</div>Commit history is not available right now.</div>';
      return;
    }

    meta.textContent = `Showing ${DocsHelpers.compactNumber(commits.length)} commits fetched from the repository history.`;
    node.innerHTML = commits.map((commit) => {
      const sha = (commit.sha || "").slice(0, 7);
      const message = (commit.commit?.message || "Commit").split("\n")[0];
      const author = commit.commit?.author?.name || commit.author?.login || "Unknown";
      const date = commit.commit?.author?.date;

      return `
        <a class="dev-history-item" href="${commit.html_url}" target="_blank" rel="noopener noreferrer">
          <div class="dev-history-item-title">${DocsHelpers.escapeHtml(message)}</div>
          <div class="dev-history-item-meta">${DocsHelpers.escapeHtml(sha)} | ${DocsHelpers.escapeHtml(author)} | ${DocsHelpers.formatDate(date)} (${DocsHelpers.formatRelativeTime(date)})</div>
        </a>
      `;
    }).join("");
  }

  function setHistoryLoading(message) {
    const node = element(selectors.historyBody);
    const meta = element(selectors.historyMeta);
    if (!node || !meta) {
      return;
    }

    meta.textContent = message;
    node.innerHTML = '<div class="callout callout-info"><div class="callout-title">History</div>Loading repository commit history from GitHub...</div>';
  }

  function setHistoryError(message) {
    const node = element(selectors.historyBody);
    const meta = element(selectors.historyMeta);
    if (!node || !meta) {
      return;
    }

    meta.textContent = "Commit history could not be loaded.";
    node.innerHTML = `
      <div class="callout callout-warn">
        <div class="callout-title">History</div>
        ${DocsHelpers.escapeHtml(message)}
      </div>
    `;
  }

  function openHistoryWindow() {
    const backdrop = element(selectors.historyBackdrop);
    if (!backdrop) {
      return;
    }

    backdrop.hidden = false;
    document.body.classList.add("dev-history-open");
    historyOpen = true;
  }

  function closeHistoryWindow() {
    const backdrop = element(selectors.historyBackdrop);
    if (!backdrop) {
      return;
    }

    backdrop.hidden = true;
    document.body.classList.remove("dev-history-open");
    historyOpen = false;
  }

  function isHistoryOpen() {
    return historyOpen;
  }

  async function fetchAllCommits() {
    const allCommits = [];
    let page = 1;

    while (true) {
      const commits = await fetchJson(DocsHelpers.githubApi(`/commits?per_page=100&page=${page}`));
      if (!Array.isArray(commits) || commits.length === 0) {
        break;
      }

      allCommits.push(...commits);

      if (commits.length < 100) {
        break;
      }

      page += 1;
    }

    return allCommits;
  }

  async function loadHistory() {
    if (historyLoaded) {
      renderHistory(historyCache);
      return;
    }

    if (historyLoading) {
      return;
    }

    historyLoading = true;
    setHistoryLoading("Fetching repository commit history...");

    try {
      historyCache = await fetchAllCommits();
      historyLoaded = true;
      renderHistory(historyCache);
    } catch (error) {
      setHistoryError(error.message || "Unknown error while loading commit history.");
    } finally {
      historyLoading = false;
    }
  }

  function bindHistoryControls() {
    const button = element(selectors.commitsMore);
    const closeButton = element(selectors.historyClose);
    const backdrop = element(selectors.historyBackdrop);

    button?.addEventListener("click", async () => {
      openHistoryWindow();
      await loadHistory();
    });

    closeButton?.addEventListener("click", closeHistoryWindow);

    backdrop?.addEventListener("click", (event) => {
      if (event.target === backdrop) {
        closeHistoryWindow();
      }
    });
  }

  function renderContributors(contributors) {
    const node = element(selectors.contributors);
    if (!node) {
      return;
    }

    node.innerHTML = contributors.map((person) => `
      <a class="dev-person" href="${person.html_url}" target="_blank" rel="noopener noreferrer">
        <img class="dev-person-avatar" src="${person.avatar_url}" alt="${DocsHelpers.escapeHtml(person.login)} avatar">
        <div class="dev-person-name">${DocsHelpers.escapeHtml(person.login)}</div>
        <div class="dev-person-meta">${DocsHelpers.compactNumber(person.contributions)} commits</div>
      </a>
    `).join("");
  }

  function renderTags(tags) {
    const node = element(selectors.tags);
    if (!node) {
      return;
    }

    if (!Array.isArray(tags) || tags.length === 0) {
      node.innerHTML = '<div class="callout callout-info"><div class="callout-title">Tags</div>No public tags have been published yet.</div>';
      return;
    }

    node.innerHTML = tags.slice(0, 5).map((tag) => `
      <a class="dev-list-item" href="${DocsData.github.repoUrl}/tree/${tag.name}" target="_blank" rel="noopener noreferrer">
        <div class="dev-list-title">${DocsHelpers.escapeHtml(tag.name)}</div>
        <div class="dev-list-meta">Browse repository state at this tag.</div>
      </a>
    `).join("");
  }

  function renderLinks() {
    const node = element(selectors.links);
    if (!node) {
      return;
    }

    const files = [
      { title: "VERSION", path: "VERSION", copy: "Single-source release marker." },
      { title: "CHANGELOG", path: "CHANGELOG.md", copy: "Version-to-version changes and release notes." },
      { title: "ROADMAP", path: "ROADMAP.md", copy: "Planned next steps for the project." },
      { title: "LICENSE", path: "LICENSE", copy: "Current licensing and usage terms." },
      { title: "SECURITY", path: "SECURITY.md", copy: "How to report framework security issues responsibly." }
    ];

    node.innerHTML = files.map((file) => `
      <a class="raw-link-card" href="${DocsHelpers.githubRaw(file.path)}" data-raw-title="${file.title}">
        <div class="dev-card-title">${DocsHelpers.escapeHtml(file.title)}</div>
        <div class="dev-card-copy">${DocsHelpers.escapeHtml(file.copy)}</div>
        <div class="dev-list-meta">Click to preview inline</div>
      </a>
    `).join("");
  }

  async function bind() {
    if (!hasPage()) {
      return;
    }

    bindHistoryControls();
    renderLinks();
    setPulse("Fetching live GitHub development data...");

    const [repoResult, commitsResult, contributorsResult, tagsResult, releaseResult] = await Promise.allSettled([
      fetchJson(DocsHelpers.githubApi("")),
      fetchJson(DocsHelpers.githubApi("/commits?per_page=20")),
      fetchJson(DocsHelpers.githubApi("/contributors?per_page=6")),
      fetchJson(DocsHelpers.githubApi("/tags?per_page=5")),
      fetchJson(DocsHelpers.githubApi("/releases/latest"))
    ]);

    if (repoResult.status === "fulfilled") {
      renderRepoSummary(repoResult.value);
      setPulse(`Live GitHub data loaded from ${DocsData.github.repo}. Last push ${DocsHelpers.formatRelativeTime(repoResult.value.pushed_at)}.`);
    } else {
      setPulse("GitHub API data could not be loaded right now. Direct repository links are still available below.", "warn");
    }

    if (repoResult.status === "fulfilled") {
      const releaseValue = releaseResult.status === "fulfilled" ? releaseResult.value : { message: "No release" };
      const tagsValue = tagsResult.status === "fulfilled" ? tagsResult.value : [];
      renderReleaseSummary(repoResult.value, releaseValue, tagsValue);
    }

    if (commitsResult.status === "fulfilled") {
      renderCommits(commitsResult.value);
      renderCommitChart(commitsResult.value);
    } else {
      const chart = element(selectors.chart);
      if (chart) {
        chart.innerHTML = '<div class="callout callout-warn"><div class="callout-title">Commit Trend</div>The graph could not be built right now because commit data was unavailable.</div>';
      }
    }

    if (contributorsResult.status === "fulfilled") {
      renderContributors(contributorsResult.value);
    }

    if (tagsResult.status === "fulfilled") {
      renderTags(tagsResult.value);
    }
  }

  return { bind, closeHistoryWindow, isHistoryOpen };
})();
