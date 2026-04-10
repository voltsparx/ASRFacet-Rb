const DocsData = (() => {
  const pages = {
    "index.html": { title: "Overview", short: "Home" },
    "getting-started.html": { title: "Getting Started", short: "Start" },
    "download.html": { title: "Download Center", short: "DL" },
    "workflow.html": { title: "Workflow", short: "Flow" },
    "cli-reference.html": { title: "CLI Reference", short: "CLI" },
    "modes.html": { title: "Modes & Examples", short: "Modes" },
    "reporting.html": { title: "Reporting & Config", short: "Reports" },
    "development.html": { title: "Development", short: "Dev" },
    "project.html": { title: "Project", short: "Project" }
  };

  const entries = [
    { id: "home", title: "Overview", page: "index.html", hint: "Landing page, capabilities, release status, and site map.", group: "Start Here" },
    { id: "core-idea", title: "Core Idea", page: "index.html", hint: "One-line framework identity and philosophy.", group: "Start Here" },
    { id: "how-it-works", title: "How It Works", page: "index.html", hint: "High-level pipeline flow in five blocks.", group: "Start Here" },
    { id: "quickstart-30", title: "Quick Start (30s)", page: "index.html", hint: "Clone, install, verify, and run in five lines.", group: "Start Here" },
    { id: "fit-check", title: "Use It / Skip It", page: "index.html", hint: "Fast fit-check for deciding when ASRFacet-Rb is the right tool.", group: "Start Here" },
    { id: "release-signals", title: "Release Signals", page: "index.html", hint: "Version, changelog, and roadmap trust markers.", group: "Start Here" },
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
    { id: "samples", title: "Sample Outputs", page: "reporting.html", hint: "See realistic CLI, JSON, and relationship output examples.", group: "Reports" },
    { id: "config", title: "Configuration", page: "reporting.html", hint: "Defaults, overrides, and operator config behavior.", group: "Reports" },
    { id: "storage", title: "Files & Storage", page: "reporting.html", hint: "Where reports, memory, sessions, and lab data live.", group: "Reports" },
    { id: "testing", title: "Testing", page: "reporting.html", hint: "Rake verification, smoke tests, and release checks.", group: "Reports" },
    { id: "development-home", title: "Development", page: "development.html", hint: "Live GitHub-powered project pulse, repository snapshot, and commit trends.", group: "Project" },
    { id: "repo-activity", title: "Repository Activity", page: "development.html", hint: "Recent commits, contributors, and branch-level movement from GitHub.", group: "Project" },
    { id: "release-radar", title: "Release Radar", page: "development.html", hint: "Tags, release signals, workflow links, and inline raw file previews.", group: "Project" },
    { id: "author", title: "Project & License", page: "project.html", hint: "Author, repository, license, and publishing context.", group: "Project" },
    { id: "signals", title: "Versioning Signals", page: "project.html", hint: "Version, changelog, roadmap, and release trust markers.", group: "Project" }
  ];

  const groups = ["Start Here", "Downloads", "Pipeline", "Operators", "Modes", "Reports", "Project"];

  const github = {
    owner: "voltsparx",
    repo: "ASRFacet-Rb",
    branch: "main",
    profileUrl: "https://github.com/voltsparx",
    repoUrl: "https://github.com/voltsparx/ASRFacet-Rb"
  };

  return { pages, entries, groups, github };
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
  workflowRail: document.getElementById("workflow-visual-rail"),
  workflowDetail: document.getElementById("workflow-visual-detail"),
  homeWorkflowRail: document.getElementById("home-workflow-rail"),
  homeWorkflowDetail: document.getElementById("home-workflow-detail"),
  homeHeroLogo: document.getElementById("home-hero-logo"),
  homeHeroEgg: document.getElementById("home-hero-egg"),
  siteFooter: document.getElementById("site-footer"),
  title: document.querySelector("title")
};
