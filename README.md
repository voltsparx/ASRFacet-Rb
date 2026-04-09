# ASRFacet-Rb

<p align="center">
  <img src="https://raw.githubusercontent.com/voltsparx/ASRFacet-Rb/refs/heads/main/docs/images/illustration/asrfacet-rb-logo.png" alt="ASRFacet-Rb Logo" width="720">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/tests-52%2F52%20passing-2E8B57?style=for-the-badge" alt="Tests Passing">
  <img src="https://img.shields.io/badge/verify-bundle%20exec%20rake%20passing-2E8B57?style=for-the-badge" alt="Rake Verify Passing">
  <br>
  <img src="https://img.shields.io/badge/status-stable-4C956C?style=for-the-badge" alt="Status Stable">
  <img src="https://img.shields.io/badge/license-Proprietary-8B0000?style=for-the-badge" alt="License">
  <br>
  <a href="https://github.com/voltsparx/ASRFacet-Rb/actions/workflows/ci.yml"><img src="https://github.com/voltsparx/ASRFacet-Rb/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/voltsparx/ASRFacet-Rb/actions/workflows/pages.yml"><img src="https://github.com/voltsparx/ASRFacet-Rb/actions/workflows/pages.yml/badge.svg" alt="Docs Website"></a>
</p>

ASRFacet-Rb is a pipeline-based reconnaissance framework for authorized testing, built to track, correlate, and evolve attack surface intelligence over time.  
It is designed for repeatable operator workflows, not one-off scans.  
Core idea: **recon that builds relationships, not just lists**.

Project website: [https://voltsparx.github.io/ASRFacet-Rb/](https://voltsparx.github.io/ASRFacet-Rb/)

## Why This Exists

Most recon tools optimize for one-time output. That creates three common problems:

- Results are scattered across disconnected commands.
- Findings are hard to compare between runs.
- Relationships between domains, IPs, services, and changes are lost.

ASRFacet-Rb addresses this with:

- A stage-driven pipeline.
- Structured multi-format output.
- Relationship-aware correlation.
- Memory-backed change tracking.

## Visual Pipeline

```text
[ Passive Discovery ]
        ->
[ Active Validation ]
        ->
[ Service and Web Mapping ]
        ->
[ Correlation Engine ]
        ->
[ Tracking and Change Summary ]
```

## Engine Model

ASRFacet-Rb names its internal systems as a clear execution model:

- `Discovery Engine`: passive sources, DNS expansion, candidate generation.
- `Validation Engine`: scoped DNS/port/HTTP confirmation.
- `Correlation Engine`: graph links, scoring, and prioritization.
- `Tracking Engine`: recon memory and run-to-run change detection.

Execution boundaries stay strict:

- Scheduler decides.
- Engines execute.
- Investigator reacts.
- Fusion/store persists.

## When To Use / When Not To Use

Use it if:

- You want repeatable recon pipelines.
- You care about relationships between assets.
- You need offline-capable reporting and historical tracking.

Do not use it if:

- You only want very fast one-command spray scans.
- You need a fully hosted cloud GUI instead of local-first workflows.
- You do not care about structured, reusable output.

## 30-Second Quick Start

```bash
git clone https://github.com/voltsparx/ASRFacet-Rb.git
cd ASRFacet-Rb
bundle install
bundle exec rake
bundle exec ruby bin/asrfacet-rb scan example.com --passive-only
```

## Installation Paths

Repository installers:

- `install/windows.ps1`
- `install/macos.sh`
- `install/linux.sh`

Website download installers:

- `docs/website/web_assets/installers/asrfacet-rb-installer-windows.ps1`
- `docs/website/web_assets/installers/asrfacet-rb-installer-windows.cmd`
- `docs/website/web_assets/installers/asrfacet-rb-installer-macos.sh`
- `docs/website/web_assets/installers/asrfacet-rb-installer-linux.sh`

Installed command aliases:

- `asrfacet-rb`
- `asrfrb`

## Command Examples

```bash
bundle exec ruby bin/asrfacet-rb scan example.com --format html --output report.html
bundle exec ruby bin/asrfacet-rb passive example.com --format json --output passive.json
bundle exec ruby bin/asrfacet-rb ports api.example.com --ports top1000
bundle exec ruby bin/asrfacet-rb dns example.com
bundle exec ruby bin/asrfacet-rb --console
bundle exec ruby bin/asrfacet-rb --web-session
bundle exec ruby bin/asrfacet-rb about
bundle exec ruby bin/asrfacet-rb --explain scope
```

## Output and Storage

Output formats:

- `cli`
- `txt`
- `html`
- `json`

Persistent paths:

- `~/.asrfacet_rb/output/`
- `~/.asrfacet_rb/memory/`
- `~/.asrfacet_rb/web_sessions/`

## Why Not Just Use X Tool?

Traditional recon tools are often great at point-in-time enumeration.  
ASRFacet-Rb is focused on **continuous, structured, and relational intelligence** with operator memory and change tracking built in.

## Trust Signals

- Version file: [`VERSION`](/VERSION)
- Changelog: [`CHANGELOG.md`](/CHANGELOG.md)
- Roadmap: [`ROADMAP.md`](/ROADMAP.md)
- Website docs: [https://voltsparx.github.io/ASRFacet-Rb/](https://voltsparx.github.io/ASRFacet-Rb/)

## Documentation Map

- [`docs/getting-started.md`](/docs/getting-started.md)
- [`docs/architecture.md`](/docs/architecture.md)
- [`docs/web-session.md`](/docs/web-session.md)
- [`docs/reporting.md`](/docs/reporting.md)
- [`docs/lab.md`](/docs/lab.md)
- [`docs/publishing.md`](/docs/publishing.md)

## Test and Verify

```bash
bundle exec rake
bundle exec rake spec
bundle exec rake test:cli
bundle exec rake test:web
bundle exec rake test:lab
bundle exec rake test:install
bundle exec rake test:website_installers
```

Latest local verification in this repo:

- Date: `2026-04-09`
- Result: `53 examples, 0 failures`
- Full verify gate: `bundle exec rake` passed

## Authorized Use

Use ASRFacet-Rb only on systems you own or have explicit written permission to test.

## License

Proprietary custom license. See [`LICENSE`](/LICENSE).

## Author

- Handle: `voltsparx`
- Email: `voltsparx@gmail.com`
- Repository: [https://github.com/voltsparx/ASRFacet-Rb](https://github.com/voltsparx/ASRFacet-Rb)
