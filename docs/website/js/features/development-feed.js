const DevelopmentFeed = (() => {
  const selectors = {
    repoSummary: "#dev-repo-summary",
    profileSummary: "#dev-profile-summary",
    releaseSummary: "#dev-release-summary",
    commits: "#dev-commits-list",
    contributors: "#dev-contributors-list",
    tags: "#dev-tags-list",
    links: "#dev-link-grid",
    pulse: "#dev-pulse"
  };

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
      <div class="dev-meta-list">
        <div><span>Default branch</span><strong>${DocsHelpers.escapeHtml(repo.default_branch || "main")}</strong></div>
        <div><span>Last push</span><strong>${DocsHelpers.formatDate(repo.pushed_at)} (${DocsHelpers.formatRelativeTime(repo.pushed_at)})</strong></div>
        <div><span>Repo</span><strong><a href="${repo.html_url}" target="_blank" rel="noopener noreferrer">${DocsHelpers.escapeHtml(repo.full_name)}</a></strong></div>
      </div>
    `;
  }

  function renderProfileSummary(profile) {
    const node = element(selectors.profileSummary);
    if (!node) {
      return;
    }

    const name = profile.name || profile.login || DocsData.github.owner;
    const bio = profile.bio || "Maintainer profile snapshot from GitHub.";

    node.innerHTML = `
      <div class="dev-profile-head">
        <img class="dev-avatar" src="${profile.avatar_url}" alt="${DocsHelpers.escapeHtml(name)} avatar">
        <div>
          <div class="dev-card-title">${DocsHelpers.escapeHtml(name)}</div>
          <div class="dev-card-copy">${DocsHelpers.escapeHtml(bio)}</div>
        </div>
      </div>
      <div class="dev-stat-grid">
        <div class="dev-stat"><span class="dev-stat-label">Followers</span><span class="dev-stat-value">${DocsHelpers.compactNumber(profile.followers)}</span></div>
        <div class="dev-stat"><span class="dev-stat-label">Public Repos</span><span class="dev-stat-value">${DocsHelpers.compactNumber(profile.public_repos)}</span></div>
        <div class="dev-stat"><span class="dev-stat-label">Following</span><span class="dev-stat-value">${DocsHelpers.compactNumber(profile.following)}</span></div>
      </div>
      <div class="dev-meta-list">
        <div><span>Profile</span><strong><a href="${profile.html_url}" target="_blank" rel="noopener noreferrer">@${DocsHelpers.escapeHtml(profile.login)}</a></strong></div>
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

    node.innerHTML = commits.map((commit) => {
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

    renderLinks();
    setPulse("Fetching live GitHub development data...");

    const [repoResult, profileResult, commitsResult, contributorsResult, tagsResult, releaseResult] = await Promise.allSettled([
      fetchJson(DocsHelpers.githubApi("")),
      fetchJson(DocsHelpers.githubProfileApi()),
      fetchJson(DocsHelpers.githubApi("/commits?per_page=6")),
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

    if (profileResult.status === "fulfilled") {
      renderProfileSummary(profileResult.value);
    }

    if (repoResult.status === "fulfilled") {
      const releaseValue = releaseResult.status === "fulfilled" ? releaseResult.value : { message: "No release" };
      const tagsValue = tagsResult.status === "fulfilled" ? tagsResult.value : [];
      renderReleaseSummary(repoResult.value, releaseValue, tagsValue);
    }

    if (commitsResult.status === "fulfilled") {
      renderCommits(commitsResult.value);
    }

    if (contributorsResult.status === "fulfilled") {
      renderContributors(contributorsResult.value);
    }

    if (tagsResult.status === "fulfilled") {
      renderTags(tagsResult.value);
    }
  }

  return { bind };
})();
