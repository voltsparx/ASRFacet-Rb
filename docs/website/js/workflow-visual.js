const WorkflowVisual = (() => {
  const stages = [
    {
      order: "01",
      name: "Passive Discovery",
      short: "Collect candidate hosts before active traffic begins.",
      detail: "This stage pulls in low-noise intelligence from certificate transparency, passive DNS, and historical archive-style sources so the framework starts with context instead of blind guesses."
    },
    {
      order: "02",
      name: "Active Validation",
      short: "Confirm scope, DNS truth, and reachable surfaces.",
      detail: "Validated names move through scoped checks, DNS confirmation, and bounded network validation so later stages work from verified assets instead of assumptions."
    },
    {
      order: "03",
      name: "Service + Web Map",
      short: "Turn live hosts into service and application context.",
      detail: "Open ports, banners, HTTP responses, crawl paths, forms, and JavaScript endpoints are gathered here to describe how a host behaves, not just that it exists."
    },
    {
      order: "04",
      name: "Correlation",
      short: "Link assets, findings, and relationships together.",
      detail: "The framework joins domains, IPs, services, and discoveries into a graph-friendly view so operators can see how assets relate and which ones deserve attention first."
    },
    {
      order: "05",
      name: "Tracking",
      short: "Preserve history and show what changed since last time.",
      detail: "Recon memory stores prior state so each run can produce deltas, change summaries, and more useful reporting instead of isolated snapshots."
    }
  ];

  function renderDetail(stage) {
    if (!DocsElements.workflowDetail || !stage) {
      return;
    }

    DocsElements.workflowDetail.innerHTML = `
      <div class="workflow-visual-detail-title">${stage.order} &middot; ${stage.name}</div>
      <div class="workflow-visual-detail-copy">${stage.detail}</div>
    `;
  }

  function activate(stageName) {
    if (!DocsElements.workflowRail) {
      return;
    }

    const stage = stages.find((entry) => entry.name === stageName) || stages[0];
    DocsElements.workflowRail.querySelectorAll(".workflow-stage").forEach((node) => {
      node.classList.toggle("is-active", node.dataset.stageName === stage.name);
    });
    renderDetail(stage);
  }

  function bind() {
    if (!DocsElements.workflowRail) {
      return;
    }

    DocsElements.workflowRail.innerHTML = stages.map((stage) => `
      <button type="button" class="workflow-stage" data-stage-name="${stage.name}">
        <span class="workflow-stage-order">${stage.order}</span>
        <div class="workflow-stage-name">${stage.name}</div>
        <div class="workflow-stage-copy">${stage.short}</div>
        <span class="workflow-stage-arrow">></span>
      </button>
    `).join("");

    DocsElements.workflowRail.querySelectorAll(".workflow-stage").forEach((node) => {
      node.addEventListener("click", () => activate(node.dataset.stageName));
      node.addEventListener("mouseenter", () => {
        if (window.matchMedia("(hover: hover)").matches) {
          activate(node.dataset.stageName);
        }
      });
    });

    activate(stages[0].name);
  }

  return { bind };
})();
