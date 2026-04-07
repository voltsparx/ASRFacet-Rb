# ASRFacet-Rb Documentation

ASRFacet-Rb is a Ruby 3.2+ authorized attack surface reconnaissance framework for operators who need one tool for discovery, validation, reporting, and repeatable baselining.

This documentation set is written for first-release use. It focuses on how to install the framework, how the pipeline behaves, how the web session UI works, where output is stored, and what was verified before publish.

## Documentation Map

- [Getting Started](./getting-started.md)
  First install, first scan, common commands, and output locations.
- [Architecture](./architecture.md)
  Pipeline stages, execution engines, resilience controls, and data flow.
- [Web Session Guide](./web-session.md)
  Local control panel behavior, saved sessions, autosave, and recovery.
- [Reporting Guide](./reporting.md)
  CLI, TXT, HTML, JSON, JSONL, report bundles, and artifact locations.
- [Publishing Notes](./publishing.md)
  First-release readiness notes, test verification, and release checklist.

## Core Principles

- Authorized use only. Run the framework only on systems you own or have explicit written permission to test.
- Scope first. Allowlists and exclusions should be set before active probing.
- Stability before speed. The framework favors bounded concurrency, retries, circuit breakers, and persistent output over brittle high-speed behavior.
- Human-friendly output. JSON is available for automation, while CLI, TXT, and HTML focus on operator-readable explanations and prioritization.

## Quick Links

- Project entrypoint: `bin/asrfacet-rb`
- Default output root: `~/.asrfacet_rb/output`
- Web session drafts: `~/.asrfacet_rb/web_sessions`
- Recon memory: `~/.asrfacet_rb/memory`
- Local web control panel: `asrfacet-rb --web-session`
