const RawPopup = (() => {
  const rawPrefix = `${DocsHelpers.githubRaw("")}`;
  let isBound = false;
  let viewer = null;
  let viewerTitle = null;
  let viewerMeta = null;
  let viewerBody = null;
  let viewerRawLink = null;
  let viewerRepoLink = null;
  let open = false;

  function ensureViewer() {
    if (viewer) {
      return viewer;
    }

    const backdrop = document.createElement("div");
    backdrop.className = "raw-viewer-backdrop";
    backdrop.hidden = true;
    backdrop.innerHTML = `
      <div class="raw-viewer-window" role="dialog" aria-modal="true" aria-label="Repository file preview">
        <div class="raw-viewer-head">
          <div>
            <div class="raw-viewer-title">Repository File</div>
            <div class="raw-viewer-meta"></div>
          </div>
          <button type="button" class="raw-viewer-close" aria-label="Close file preview">Close</button>
        </div>
        <div class="raw-viewer-actions">
          <a class="raw-viewer-link" data-role="raw" href="#" target="_blank" rel="noopener noreferrer">Open Raw</a>
          <a class="raw-viewer-link" data-role="repo" href="#" target="_blank" rel="noopener noreferrer">View On GitHub</a>
        </div>
        <pre class="raw-viewer-body">Loading...</pre>
      </div>
    `;

    document.body.appendChild(backdrop);

    viewer = backdrop;
    viewerTitle = backdrop.querySelector(".raw-viewer-title");
    viewerMeta = backdrop.querySelector(".raw-viewer-meta");
    viewerBody = backdrop.querySelector(".raw-viewer-body");
    viewerRawLink = backdrop.querySelector('[data-role="raw"]');
    viewerRepoLink = backdrop.querySelector('[data-role="repo"]');

    backdrop.addEventListener("click", (event) => {
      if (event.target === backdrop) {
        close();
      }
    });

    backdrop.querySelector(".raw-viewer-close")?.addEventListener("click", close);
    return viewer;
  }

  function deriveRepoPath(href) {
    if (!href || !href.startsWith(rawPrefix)) {
      return null;
    }

    return href.slice(rawPrefix.length);
  }

  function decodeBase64(text = "") {
    const normalized = text.replace(/\n/g, "");
    const bytes = Uint8Array.from(atob(normalized), (char) => char.charCodeAt(0));
    return new TextDecoder("utf-8").decode(bytes);
  }

  async function fetchFileContent(path) {
    const response = await fetch(DocsHelpers.githubApi(`/contents/${path}?ref=${DocsData.github.branch}`), {
      headers: { Accept: "application/vnd.github+json" }
    });

    if (!response.ok) {
      throw new Error(`GitHub returned ${response.status}`);
    }

    const payload = await response.json();
    if (!payload.content) {
      throw new Error("No repository content was returned.");
    }

    return decodeBase64(payload.content);
  }

  function showLoading(title, path, rawHref) {
    ensureViewer();
    viewerTitle.textContent = title || "Repository File";
    viewerMeta.textContent = `${path} | fetched from GitHub`;
    viewerBody.textContent = "Loading file preview...";
    viewerRawLink.href = rawHref;
    viewerRepoLink.href = DocsHelpers.githubBlob(path);
    viewer.hidden = false;
    document.body.classList.add("raw-viewer-open");
    open = true;
  }

  function showContent(title, path, content) {
    if (!viewerBody) {
      return;
    }

    viewerTitle.textContent = title || "Repository File";
    viewerMeta.textContent = `${path} | inline preview`;
    viewerBody.textContent = content;
  }

  function showError(title, path, message) {
    if (!viewerBody) {
      return;
    }

    viewerTitle.textContent = title || "Repository File";
    viewerMeta.textContent = `${path} | preview unavailable`;
    viewerBody.textContent = `Unable to load this file preview.\n\n${message}\n\nUse the buttons above to open the raw file or the GitHub repository view directly.`;
  }

  async function openLink(link) {
    const href = link.getAttribute("href") || "";
    const path = deriveRepoPath(href);

    if (!path) {
      return;
    }

    const title = link.dataset.rawTitle || link.textContent.trim() || path.split("/").pop();
    showLoading(title, path, href);

    try {
      const content = await fetchFileContent(path);
      showContent(title, path, content);
    } catch (error) {
      showError(title, path, error.message || "Unknown error.");
    }
  }

  function close() {
    if (!viewer) {
      return;
    }

    viewer.hidden = true;
    document.body.classList.remove("raw-viewer-open");
    open = false;
  }

  function isOpen() {
    return open;
  }

  function bind() {
    if (isBound) {
      return;
    }

    document.addEventListener("click", (event) => {
      const target = event.target;
      if (!(target instanceof HTMLElement)) {
        return;
      }

      const link = target.closest("a");
      if (!link) {
        return;
      }

      if (link.closest(".raw-viewer-actions")) {
        return;
      }

      const href = link.getAttribute("href") || "";
      if (!href.startsWith(rawPrefix)) {
        return;
      }

      if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) {
        return;
      }

      event.preventDefault();
      void openLink(link);
    });

    isBound = true;
  }

  return { bind, close, isOpen };
})();
