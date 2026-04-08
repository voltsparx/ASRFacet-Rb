# ASRFacet-Rb

<p align="center">
  <img src="https://raw.githubusercontent.com/voltsparx/ASRFacet-Rb/refs/heads/main/docs/images/illustration/asrfacet-rb-logo.png" alt="ASRFacet-Rb Logo" width="720">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-0A66C2?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/ruby-%3E%3D%203.2-red?style=for-the-badge&logo=ruby&logoColor=white" alt="Ruby >= 3.2">
  <a href="https://github.com/voltsparx/ASRFacet-Rb/actions/workflows/ci.yml"><img src="https://github.com/voltsparx/ASRFacet-Rb/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/voltsparx/ASRFacet-Rb/actions/workflows/pages.yml"><img src="https://github.com/voltsparx/ASRFacet-Rb/actions/workflows/pages.yml/badge.svg" alt="Docs Website"></a><br>
  <img src="https://img.shields.io/badge/tests-51%2F51%20passing-2E8B57?style=for-the-badge" alt="Tests Passing">
  <img src="https://img.shields.io/badge/verify-bundle%20exec%20rake%20passing-2E8B57?style=for-the-badge" alt="Rake Verify Passing"><br>
  <img src="https://img.shields.io/badge/status-stable-4C956C?style=for-the-badge" alt="Status Stable">
  <img src="https://img.shields.io/badge/license-Proprietary-8B0000?style=for-the-badge" alt="License">
</p>

ASRFacet-Rb is a Ruby 3.2+ attack surface reconnaissance framework for authorized security testing. It combines passive discovery, recursive DNS and certificate enrichment, service mapping, HTTP fingerprinting, crawl analysis, JavaScript endpoint mining, change tracking, correlation, and offline reporting in a single operator-focused workflow.

Current framework version: `1.0.0`

## Documentation

The full first-release documentation set lives in `docs/`.

- `docs/index.md`
- `docs/getting-started.md`
- `docs/architecture.md`
- `docs/web-session.md`
- `docs/reporting.md`
- `docs/lab.md`
- `docs/publishing.md`

Repository automation now includes:

- GitHub Actions CI in `.github/workflows/ci.yml` running `bundle exec rake`
- GitHub Pages deployment in `.github/workflows/pages.yml` publishing `docs/website/`

Execution ownership stays intentionally strict: the scheduler owns orchestration,
execution helpers run work, and engines do not create their own competing
control loops.

The current README reflects the latest verified release-style test run on April 8, 2026: `bundle exec rake` completed successfully, including `51 examples, 0 failures`, CLI smoke checks, web-session smoke checks, local lab smoke checks, installer smoke checks, and a clean gem build.

## Authorized Use

Use ASRFacet-Rb only on systems you own or have explicit written permission to test. The framework is built to help operators stay inside scope through allow lists, exclusion lists, recon memory, and beginner-friendly explanations.

## What It Does

<table>
  <thead>
    <tr>
      <th>Area</th>
      <th>Purpose</th>
      <th>Built-In Capability</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Passive Discovery</td>
      <td>Collect known assets before touching the target</td>
      <td>crt.sh, HackerTarget, Wayback, RapidDNS, AlienVault, Shodan, ThreatCrowd, BufferOver</td>
    </tr>
    <tr>
      <td>Asset Validation</td>
      <td>Confirm whether discovered assets are real and reachable</td>
      <td>DNS lookups, certificate SAN pivots, DNS busting, scope filtering</td>
    </tr>
    <tr>
      <td>Service Mapping</td>
      <td>Identify exposed network services</td>
      <td>Threaded TCP port scanning with banner grabbing</td>
    </tr>
    <tr>
      <td>Web Recon</td>
      <td>Fingerprint applications and discover web exposure</td>
      <td>HTTP probing, path checks, crawling, JavaScript endpoint extraction</td>
    </tr>
    <tr>
      <td>Prioritization</td>
      <td>Highlight the most interesting assets first</td>
      <td>Asset scoring, findings, correlation, change tracking</td>
    </tr>
    <tr>
      <td>Operator UX</td>
      <td>Make the framework teach while it runs</td>
      <td>CLI help, <code>about</code>, <code>explain</code>, manual, Metasploit-style console, wizard mode, first-run guidance</td>
    </tr>
    <tr>
      <td>Local Validation</td>
      <td>Test the framework before real authorized targets</td>
      <td>Built-in <code>lab</code> mode with placeholder web and API surfaces</td>
    </tr>
  </tbody>
</table>

## Installation

```bash
bundle install
bundle exec rake
bundle exec ruby bin/asrfacet-rb help
bundle exec ruby bin/asrfacet-rb about
bundle exec ruby bin/asrfacet-rb --explain scope
```

Cross-platform installers are also available in `install/`:

```text
install/windows.ps1   # install | test | uninstall | update
install/macos.sh      # install | test | uninstall | update
install/linux.sh      # install | test | uninstall | update
```

The installers stage ASRFacet-Rb into its own `asrfacet-rb` application folder, create launchers on your user `PATH`, keep dependencies inside the install directory, and support a repo-local `test` mode that does not touch your system install. After installation, both `asrfacet-rb` and `asrfrb` are available as system commands that point to the same application.
On macOS and Linux they also add the installed `man/` directory to `MANPATH`, and all installers print the install path, launcher path, and default stored-report location when they finish.

For local manual-page testing:

```bash
MANPATH="$PWD/man:$MANPATH" man asrfacet-rb
```

## Testing

Use the Rake-based verification flow for routine checks:

```bash
bundle exec rake
bundle exec rake spec
bundle exec rake test:cli
bundle exec rake test:web
bundle exec rake test:lab
bundle exec rake test:install
```

There is also a reusable script harness under `test/`:

```bash
ruby test/run_all.rb
```

## Quick Start

<table>
  <thead>
    <tr>
      <th>Goal</th>
      <th>Command</th>
      <th>What It Does</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Full recon</td>
      <td><code>bundle exec ruby bin/asrfacet-rb scan example.com</code></td>
      <td>Runs the complete pipeline from passive collection through findings</td>
    </tr>
    <tr>
      <td>Passive-only footprinting</td>
      <td><code>bundle exec ruby bin/asrfacet-rb passive example.com</code></td>
      <td>Queries passive sources without active probing</td>
    </tr>
    <tr>
      <td>Port-focused validation</td>
      <td><code>bundle exec ruby bin/asrfacet-rb ports api.example.com --ports top1000</code></td>
      <td>Scans only ports and exposed services</td>
    </tr>
    <tr>
      <td>DNS-only inventory</td>
      <td><code>bundle exec ruby bin/asrfacet-rb dns example.com</code></td>
      <td>Collects DNS records and resolution data</td>
    </tr>
    <tr>
      <td>About the framework</td>
      <td><code>bundle exec ruby bin/asrfacet-rb about</code></td>
      <td>Prints the framework overview, safety model, and storage paths</td>
    </tr>
    <tr>
      <td>Local validation lab</td>
      <td><code>bundle exec ruby bin/asrfacet-rb lab</code></td>
      <td>Starts a safe local target for dry-runs before real systems</td>
    </tr>
    <tr>
      <td>Interactive shell</td>
      <td><code>bundle exec ruby bin/asrfacet-rb --console</code></td>
      <td>Opens the framework console and beginner wizard</td>
    </tr>
    <tr>
      <td>Web control panel</td>
      <td><code>bundle exec ruby bin/asrfacet-rb --web-session</code></td>
      <td>Starts the local browser UI with saved sessions, live activity, and report browsing</td>
    </tr>
    <tr>
      <td>Manual</td>
      <td><code>bundle exec ruby bin/asrfacet-rb manual workflow</code></td>
      <td>Prints a focused manual section</td>
    </tr>
  </tbody>
</table>

## Command Reference

<table>
  <thead>
    <tr>
      <th>Command</th>
      <th>Aliases</th>
      <th>Description</th>
      <th>Typical Use</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>scan DOMAIN</code></td>
      <td><code>s</code>, <code>sc</code></td>
      <td>Run the full reconnaissance pipeline</td>
      <td>Main entrypoint for complete attack-surface mapping</td>
    </tr>
    <tr>
      <td><code>passive DOMAIN</code></td>
      <td><code>p</code>, <code>pa</code></td>
      <td>Run passive source aggregation only</td>
      <td>Lower-noise first pass and scoping support</td>
    </tr>
    <tr>
      <td><code>ports HOST</code></td>
      <td><code>pt</code>, <code>po</code></td>
      <td>Run a focused TCP port scan</td>
      <td>Network exposure checks without the full web workflow</td>
    </tr>
    <tr>
      <td><code>dns DOMAIN</code></td>
      <td><code>d</code>, <code>dn</code></td>
      <td>Collect DNS data only</td>
      <td>Mail, naming, and resolution inventory</td>
    </tr>
    <tr>
      <td><code>lab</code></td>
      <td><code>none</code></td>
      <td>Launch a safe local validation lab</td>
      <td>Dry-run the framework against placeholder surfaces before real authorized targets</td>
    </tr>
    <tr>
      <td><code>interactive</code></td>
      <td><code>i</code>, <code>int</code></td>
      <td>Launch the guided workflow</td>
      <td>Beginner-friendly one-shot guided execution</td>
    </tr>
    <tr>
      <td><code>console</code></td>
      <td><code>c</code>, <code>con</code>, <code>shell</code></td>
      <td>Launch the persistent console shell</td>
      <td>Operator-centric usage with help, man, and wizard support</td>
    </tr>
    <tr>
      <td><code>web</code></td>
      <td><code>w</code>, <code>ui</code></td>
      <td>Launch the local web control panel</td>
      <td>Saved sessions, browser-driven configuration, and live report access</td>
    </tr>
    <tr>
      <td><code>about</code></td>
      <td><code>a</code></td>
      <td>Print a framework overview</td>
      <td>Quickly understand the framework, safety model, and storage paths</td>
    </tr>
    <tr>
      <td><code>help [TOPIC]</code></td>
      <td><code>h</code>, <code>?</code></td>
      <td>Show help or a focused explanation</td>
      <td>Fast command discovery</td>
    </tr>
    <tr>
      <td><code>explain TOPIC</code></td>
      <td><code>x</code>, <code>exp</code></td>
      <td>Explain a workflow, flag, or concept</td>
      <td>Self-documenting operator guidance</td>
    </tr>
    <tr>
      <td><code>manual [SECTION]</code></td>
      <td><code>m</code>, <code>man</code></td>
      <td>Print the built-in manual</td>
      <td>Structured framework reference</td>
    </tr>
    <tr>
      <td><code>version</code></td>
      <td><code>v</code>, <code>ver</code></td>
      <td>Print the installed version</td>
      <td>Version validation and debugging</td>
    </tr>
  </tbody>
</table>

## Global Options

<table>
  <thead>
    <tr>
      <th>Flag</th>
      <th>Meaning</th>
      <th>Why You Would Use It</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>-o, --output PATH</code></td>
      <td>Write the rendered report to disk</td>
      <td>Save HTML, JSON, TXT, or CLI output for later review</td>
    </tr>
    <tr>
      <td><code>-f, --format cli|json|html|txt</code></td>
      <td>Select the output renderer</td>
      <td>Choose terminal, machine-readable, or offline report output</td>
    </tr>
    <tr>
      <td><code>-v, --verbose</code></td>
      <td>Print stage-by-stage progress</td>
      <td>Understand where time is being spent during a run</td>
    </tr>
    <tr>
      <td><code>-t, --threads N</code></td>
      <td>Set worker concurrency</td>
      <td>Tune scan speed versus resource pressure</td>
    </tr>
    <tr>
      <td><code>--timeout SEC</code></td>
      <td>Set network timeout</td>
      <td>Adapt to slow or unstable targets</td>
    </tr>
    <tr>
      <td><code>--scope LIST</code></td>
      <td>Add allowed domains or IPs</td>
      <td>Keep active probing inside the authorized boundary</td>
    </tr>
    <tr>
      <td><code>--exclude LIST</code></td>
      <td>Block discovered assets from being touched</td>
      <td>Avoid third-party, sensitive, or inherited infrastructure</td>
    </tr>
    <tr>
      <td><code>--monitor</code></td>
      <td>Show changes since the last recorded scan</td>
      <td>Track drift between repeat recon runs</td>
    </tr>
    <tr>
      <td><code>--top N</code></td>
      <td>Limit Top Targets in CLI output</td>
      <td>Keep terminal output focused on the highest-value assets</td>
    </tr>
    <tr>
      <td><code>--memory</code></td>
      <td>Skip already confirmed subdomains</td>
      <td>Reduce repeat work when scanning the same target repeatedly</td>
    </tr>
    <tr>
      <td><code>-C, --console</code></td>
      <td>Open the persistent framework shell</td>
      <td>Use the console UI instead of a one-shot command</td>
    </tr>
    <tr>
      <td><code>--about</code></td>
      <td>Print the framework overview</td>
      <td>Shortcut flag for the <code>about</code> command</td>
    </tr>
    <tr>
      <td><code>--explain TOPIC</code></td>
      <td>Explain one topic directly</td>
      <td>Shortcut flag for the <code>explain</code> command</td>
    </tr>
    <tr>
      <td><code>--web-session</code></td>
      <td>Open the local browser-based control panel</td>
      <td>Use saved web sessions, live activity, and report browsing</td>
    </tr>
    <tr>
      <td><code>--web-host HOST</code> / <code>--web-port N</code></td>
      <td>Choose where the web panel binds locally</td>
      <td>Useful when <code>127.0.0.1:4567</code> is already in use</td>
    </tr>
  </tbody>
</table>

## Web Session Mode

`--web-session` starts a local-only control panel at `127.0.0.1:4567` by default. The dashboard lets you configure scans, save named sessions, launch runs, watch stage-by-stage activity, and open the stored CLI, TXT, HTML, and JSON reports without leaving the browser.

Session drafts are persisted under `~/.asrfacet_rb/web_sessions/`, so configuration survives accidental browser closes, process crashes, and power loss. Running sessions use heartbeats so stale runs are marked `interrupted` without clobbering a freshly active session, and `--web-host` / `--web-port` are preserved when launching through `--web-session`. The dashboard also includes an About section and an embedded documentation viewer backed by the repository `docs/` content.

## Local Validation Lab

`lab` starts a safe local target with placeholder discovery surfaces so you can validate ASRFacet-Rb before real authorized targets.

```bash
bundle exec ruby bin/asrfacet-rb lab
bundle exec ruby bin/asrfacet-rb lab --port 9393
```

The lab includes:

- a JS-heavy page with API-looking routes
- a directory-listing style page
- a permissive CORS example
- common debug and metrics endpoints
- a sanitized placeholder `.env` route
- an admin-style login form

## Scan-Specific Options

<table>
  <thead>
    <tr>
      <th>Command</th>
      <th>Flag</th>
      <th>Meaning</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>scan</code></td>
      <td><code>-p, --ports RANGE</code></td>
      <td>Choose <code>top100</code>, <code>top1000</code>, ranges like <code>1-1000</code>, or lists like <code>80,443</code></td>
    </tr>
    <tr>
      <td><code>scan</code></td>
      <td><code>--passive-only</code></td>
      <td>Use the scan entrypoint but limit execution to passive sources</td>
    </tr>
    <tr>
      <td><code>scan</code></td>
      <td><code>-w, --wordlist PATH</code></td>
      <td>Provide a custom lazy-read wordlist for active discovery</td>
    </tr>
    <tr>
      <td><code>scan</code>, <code>passive</code></td>
      <td><code>--shodan-key KEY</code></td>
      <td>Enable the Shodan passive source without storing the key in results</td>
    </tr>
    <tr>
      <td><code>ports</code></td>
      <td><code>-p, --ports RANGE</code></td>
      <td>Choose the TCP port range for a focused service scan</td>
    </tr>
  </tbody>
</table>

## Console Guide

The console is the richest interface in the framework. It is designed to feel like an operator shell and to teach how the framework works while you use it.

<table>
  <thead>
    <tr>
      <th>Console Command</th>
      <th>Purpose</th>
      <th>Beginner Value</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>show commands</code></td>
      <td>List console and framework commands</td>
      <td>Quick orientation inside the shell</td>
    </tr>
    <tr>
      <td><code>show options</code></td>
      <td>List the most useful global flags</td>
      <td>Shows what can be tuned before a run</td>
    </tr>
    <tr>
      <td><code>show workflow</code></td>
      <td>Display the pipeline stages</td>
      <td>Explains how recon flows from one stage to the next</td>
    </tr>
    <tr>
      <td><code>show config</code></td>
      <td>Print merged configuration values</td>
      <td>Makes threads, timeouts, and defaults visible</td>
    </tr>
    <tr>
      <td><code>show learning</code></td>
      <td>Explain recon methodology</td>
      <td>Teaches passive versus active recon and pivoting logic</td>
    </tr>
    <tr>
      <td><code>info TOPIC</code></td>
      <td>Explain one concept or command</td>
      <td>Fast in-shell documentation</td>
    </tr>
    <tr>
      <td><code>man [SECTION]</code></td>
      <td>Read the built-in manual inside the shell</td>
      <td>Structured long-form documentation</td>
    </tr>
    <tr>
      <td><code>wizard</code></td>
      <td>Launch the guided console planner</td>
      <td>Auto-builds a scan command and explains why</td>
    </tr>
    <tr>
      <td><code>banner</code></td>
      <td>Redraw the framework banner</td>
      <td>Console-only helper</td>
    </tr>
    <tr>
      <td><code>clear</code></td>
      <td>Clear the console screen</td>
      <td>Console-only helper</td>
    </tr>
  </tbody>
</table>

## Wizard Mode

Wizard mode exists only inside the console. It asks what you are trying to learn, how cautious you want to be, what output you want, and whether monitoring or memory should be enabled. It then recommends a concrete command and explains the reasoning behind the chosen profile.

<table>
  <thead>
    <tr>
      <th>Profile</th>
      <th>Goal</th>
      <th>Threads</th>
      <th>Ports</th>
      <th>Memory</th>
      <th>Monitor</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Cautious</td>
      <td>Low-noise confirmation-first recon</td>
      <td>25</td>
      <td>top100</td>
      <td>Enabled</td>
      <td>Disabled</td>
    </tr>
    <tr>
      <td>Balanced</td>
      <td>Normal engagement baseline</td>
      <td>50</td>
      <td>top100</td>
      <td>Enabled</td>
      <td>Enabled</td>
    </tr>
    <tr>
      <td>Deep</td>
      <td>Broader validation and service coverage</td>
      <td>100</td>
      <td>top1000</td>
      <td>Disabled</td>
      <td>Enabled</td>
    </tr>
  </tbody>
</table>

## How The Pipeline Works

<table>
  <thead>
    <tr>
      <th>Stage</th>
      <th>Engine Group</th>
      <th>Purpose</th>
      <th>Output Added</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>1</td>
      <td>Passive Runner</td>
      <td>Gather known subdomains from external sources</td>
      <td>Subdomains, passive errors</td>
    </tr>
    <tr>
      <td>2</td>
      <td>DNS + Certificate discovery</td>
      <td>Validate assets and pivot through DNS records and SANs</td>
      <td>DNS, IPs, certificates, graph edges</td>
    </tr>
    <tr>
      <td>3</td>
      <td>Permutation + DNS Buster</td>
      <td>Generate and actively validate candidate hostnames</td>
      <td>Candidate subdomains, discovered subdomains</td>
    </tr>
    <tr>
      <td>4</td>
      <td>Discovery feedback loop</td>
      <td>Feed newly found hosts back into DNS and certificate analysis</td>
      <td>Expanded asset set</td>
    </tr>
    <tr>
      <td>5</td>
      <td>Port Engine</td>
      <td>Identify reachable services on discovered IPs</td>
      <td>Open ports, banners, service nodes</td>
    </tr>
    <tr>
      <td>6</td>
      <td>HTTP + Crawl + JS + Correlation</td>
      <td>Map web exposure, paths, scripts, JS endpoints, and cross-host patterns</td>
      <td>HTTP responses, crawl data, JS endpoints, correlations, top assets</td>
    </tr>
    <tr>
      <td>7</td>
      <td>WHOIS + ASN</td>
      <td>Add ownership and infrastructure context</td>
      <td>WHOIS, ASN data</td>
    </tr>
    <tr>
      <td>8</td>
      <td>Vuln + Monitoring</td>
      <td>Generate findings, diff results, and persist recon memory</td>
      <td>Findings, change diff, probabilistic hints, memory updates</td>
    </tr>
  </tbody>
</table>

## Core Modules

<table>
  <thead>
    <tr>
      <th>Module</th>
      <th>Role</th>
      <th>Why It Matters</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>ASRFacet::Core::Target</code></td>
      <td>Normalizes the target domain and caches HTTP fetches</td>
      <td>Provides a stable base object for the run</td>
    </tr>
    <tr>
      <td><code>ASRFacet::ResultStore</code></td>
      <td>Thread-safe result collection</td>
      <td>Keeps discoveries deduplicated and serializable</td>
    </tr>
    <tr>
      <td><code>ASRFacet::EventBus</code></td>
      <td>Internal event routing</td>
      <td>Lets discovered assets feed later processing stages</td>
    </tr>
    <tr>
      <td><code>ASRFacet::Core::KnowledgeGraph</code></td>
      <td>Relationship graph for domains, IPs, services, ASNs, and findings</td>
      <td>Supports pivots like domain-to-IP or IP-to-service</td>
    </tr>
    <tr>
      <td><code>ASRFacet::Core::ReconMemory</code></td>
      <td>Persistent per-target scan history</td>
      <td>Enables monitoring and skip-known behavior</td>
    </tr>
    <tr>
      <td><code>ASRFacet::Core::ScopeEngine</code></td>
      <td>Enforces allow and exclude lists</td>
      <td>Helps prevent out-of-scope probing</td>
    </tr>
    <tr>
      <td><code>ASRFacet::Core::NoiseFilter</code></td>
      <td>Filters low-value HTTP output and duplicate findings</td>
      <td>Keeps reports focused on meaningful results</td>
    </tr>
    <tr>
      <td><code>ASRFacet::Core::CircuitBreaker</code></td>
      <td>Isolates repeatedly failing components</td>
      <td>Improves resiliency during unstable scans</td>
    </tr>
  </tbody>
</table>

## Passive Sources

<table>
  <thead>
    <tr>
      <th>Source</th>
      <th>Type</th>
      <th>Notes</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>crt.sh</td>
      <td>Certificate transparency</td>
      <td>Good source for SAN-derived subdomains</td>
    </tr>
    <tr>
      <td>HackerTarget</td>
      <td>Passive host search</td>
      <td>Returns hostnames with simple parsing</td>
    </tr>
    <tr>
      <td>Wayback</td>
      <td>Historical archive</td>
      <td>Useful for older subdomains and URLs</td>
    </tr>
    <tr>
      <td>RapidDNS</td>
      <td>Passive DNS</td>
      <td>HTML-parsed subdomain extraction</td>
    </tr>
    <tr>
      <td>AlienVault OTX</td>
      <td>Passive DNS</td>
      <td>No API key required</td>
    </tr>
    <tr>
      <td>Shodan</td>
      <td>Passive DNS</td>
      <td>Requires <code>--shodan-key</code></td>
    </tr>
    <tr>
      <td>ThreatCrowd</td>
      <td>Passive domain report</td>
      <td>Best-effort extraction of subdomains array</td>
    </tr>
    <tr>
      <td>BufferOver</td>
      <td>Passive DNS aggregation</td>
      <td>Parses FDNS and RDNS results</td>
    </tr>
  </tbody>
</table>

## Output Formats

<table>
  <thead>
    <tr>
      <th>Format</th>
      <th>Best For</th>
      <th>Includes</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>cli</code></td>
      <td>Live terminal triage</td>
      <td>Subdomains, ports, technologies, findings, top targets</td>
    </tr>
    <tr>
      <td><code>json</code></td>
      <td>Automation and downstream tooling</td>
      <td>Store data plus graph, diff, JS, correlations, and scored assets</td>
    </tr>
    <tr>
      <td><code>html</code></td>
      <td>Offline report sharing</td>
      <td>Top targets, findings, change summary, graph table, JS endpoints</td>
    </tr>
    <tr>
      <td><code>txt</code></td>
      <td>Plain export and note-taking</td>
      <td>Compact text sections for key outputs</td>
    </tr>
  </tbody>
</table>

## Configuration

Configuration is loaded from `config/default.yml` and then merged with `~/.asrfacet_rb/config.yml`.
By default, stored reports and JSONL event streams now live under `~/.asrfacet_rb/output/` so installed runs have a predictable place to review old output.

<table>
  <thead>
    <tr>
      <th>Config Key</th>
      <th>Purpose</th>
      <th>Default Direction</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>threads.default</code></td>
      <td>Fallback worker count</td>
      <td>General concurrency baseline</td>
    </tr>
    <tr>
      <td><code>threads.dns</code></td>
      <td>DNS-oriented worker tuning</td>
      <td>Used for DNS-heavy phases</td>
    </tr>
    <tr>
      <td><code>threads.http</code></td>
      <td>HTTP-oriented worker tuning</td>
      <td>Controls HTTP concurrency</td>
    </tr>
    <tr>
      <td><code>timeouts.dns</code>, <code>timeouts.port</code>, <code>timeouts.http</code>, <code>timeouts.ssl</code></td>
      <td>Network timing controls</td>
      <td>Adjust for slow or brittle targets</td>
    </tr>
    <tr>
      <td><code>wordlists.subdomain</code>, <code>wordlists.ports</code>, <code>wordlists.paths</code></td>
      <td>Bundled seed lists</td>
      <td>Framework-provided defaults</td>
    </tr>
    <tr>
      <td><code>output.directory</code></td>
      <td>Base output directory</td>
      <td>Where reports and streams are written</td>
    </tr>
    <tr>
      <td><code>resilience.circuit_breaker.threshold</code></td>
      <td>Failure threshold before a breaker opens</td>
      <td>Prevents repeated engine thrashing</td>
    </tr>
    <tr>
      <td><code>resilience.circuit_breaker.cooldown</code></td>
      <td>Cooldown before re-entry</td>
      <td>Lets unstable components recover</td>
    </tr>
    <tr>
      <td><code>http.user_agent</code>, <code>http.max_retries</code>, <code>http.follow_redirects</code>, <code>http.max_redirects</code>, <code>http.verify_ssl</code></td>
      <td>HTTP client behavior</td>
      <td>Controls request policy and retry behavior</td>
    </tr>
  </tbody>
</table>

## Files and Storage

<table>
  <thead>
    <tr>
      <th>Path</th>
      <th>Purpose</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>bin/asrfacet-rb</code></td>
      <td>Primary executable</td>
    </tr>
    <tr>
      <td><code>config/default.yml</code></td>
      <td>Project-level defaults</td>
    </tr>
    <tr>
      <td><code>~/.asrfacet_rb/config.yml</code></td>
      <td>User overrides</td>
    </tr>
    <tr>
      <td><code>~/.asrfacet_rb/memory/</code></td>
      <td>Per-target recon memory and monitoring state</td>
    </tr>
    <tr>
      <td><code>~/.asrfacet_rb/web_sessions/</code></td>
      <td>Saved web-session drafts and run state</td>
    </tr>
    <tr>
      <td><code>~/.asrfacet_rb/output/streams/&lt;target&gt;.jsonl</code></td>
      <td>Live JSONL event stream written during scans</td>
    </tr>
    <tr>
      <td><code>wordlists/</code></td>
      <td>Bundled wordlists for subdomains, ports, and paths</td>
    </tr>
    <tr>
      <td><code>man/asrfacet-rb.1</code></td>
      <td>Manual page source</td>
    </tr>
  </tbody>
</table>

## Recon Methodology Notes

<table>
  <thead>
    <tr>
      <th>Concept</th>
      <th>Meaning</th>
      <th>How ASRFacet-Rb Applies It</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Passive Recon</td>
      <td>Use third-party knowledge before touching the target</td>
      <td>Passive runner aggregates known subdomains first</td>
    </tr>
    <tr>
      <td>Active Recon</td>
      <td>Validate by making requests or opening connections</td>
      <td>DNS, ports, HTTP, crawl, and JS phases confirm exposure</td>
    </tr>
    <tr>
      <td>Pivoting</td>
      <td>Use one discovery to find another</td>
      <td>DNS records, cert SANs, and graph edges feed new assets forward</td>
    </tr>
    <tr>
      <td>Prioritization</td>
      <td>Not every asset deserves equal attention</td>
      <td>Asset scoring and findings rank what matters most</td>
    </tr>
    <tr>
      <td>Monitoring</td>
      <td>Recon is more useful when repeated over time</td>
      <td>Recon memory and diffs show new, removed, or changed assets</td>
    </tr>
  </tbody>
</table>

## Example Commands

```bash
bundle exec ruby bin/asrfacet-rb scan example.com --format html --output report.html
bundle exec ruby bin/asrfacet-rb s example.com --ports top1000 --threads 75
bundle exec ruby bin/asrfacet-rb passive example.com --format json --output passive.json
bundle exec ruby bin/asrfacet-rb p example.com --shodan-key YOUR_KEY
bundle exec ruby bin/asrfacet-rb pt 192.0.2.10 --ports 22,80,443,8443
bundle exec ruby bin/asrfacet-rb d example.com --format json
bundle exec ruby bin/asrfacet-rb scan example.com --scope example.com,api.example.com --exclude dev.example.com --monitor --memory
bundle exec ruby bin/asrfacet-rb --console
bundle exec ruby bin/asrfacet-rb m workflow
```

## Manual and Self-Documentation

ASRFacet-Rb is intentionally self-documented.

<table>
  <thead>
    <tr>
      <th>Need</th>
      <th>Command</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Main help menu</td>
      <td><code>asrfacet-rb help</code></td>
    </tr>
    <tr>
      <td>Explain one command or flag</td>
      <td><code>asrfacet-rb explain scope</code></td>
    </tr>
    <tr>
      <td>Read long-form manual text</td>
      <td><code>asrfacet-rb manual</code></td>
    </tr>
    <tr>
      <td>Read one manual section</td>
      <td><code>asrfacet-rb manual workflow</code></td>
    </tr>
    <tr>
      <td>Use the console for guided learning</td>
      <td><code>asrfacet-rb --console</code></td>
    </tr>
    <tr>
      <td>Use the system man viewer during development</td>
      <td><code>MANPATH="$PWD/man:$MANPATH" man asrfacet-rb</code></td>
    </tr>
  </tbody>
</table>

## License

ASRFacet-Rb uses a proprietary custom license. See `LICENSE`.

## Author

<table>
  <thead>
    <tr>
      <th>Field</th>
      <th>Value</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Author</td>
      <td>voltsparx</td>
    </tr>
    <tr>
      <td>Email</td>
      <td>voltsparx@gmail.com</td>
    </tr>
    <tr>
      <td>Repository</td>
      <td><a href="https://github.com/voltsparx/ASRFacet-Rb">https://github.com/voltsparx/ASRFacet-Rb</a></td>
    </tr>
  </tbody>
</table>
