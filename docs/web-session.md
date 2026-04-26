# Web Session Guide

## Launch

```bash
bundle exec ruby bin/asrfacet-rb --web-session
bundle exec ruby bin/asrfacet-rb --web-session --web-host 127.0.0.1 --web-port 4573
bundle exec ruby bin/asrfacet-rb deploy
```

The web control panel is local-only by default and binds to `127.0.0.1:4567` unless overridden.
Use `deploy` when you want the web control panel and the local validation lab to come up together with readiness checks and a runtime manifest.

## What The Dashboard Does

- create and save named sessions
- configure scan mode and options
- launch runs from the browser
- watch stage-by-stage activity
- view run summaries and saved report links
- read the built-in documentation set directly inside the dashboard
- review an about section with framework and storage details
- persist drafts across browser closes and host interruptions

## Layout Model

The current shell is organized more like a control plane than a single long page:

- a persistent left rail for workspace navigation and saved sessions
- a session builder with tabs for targeting, execution, and integrations
- a workbench for summary cards, exposure tables, and snapshot views
- a reports view for stored artifacts
- a documentation view with searchable built-in docs
- a slide-out activity drawer for live run events

## Transparency

- The dashboard is a local HTTP service, not a hosted cloud control panel.
- Saving or autosaving a session writes JSON state to `~/.asrfacet_rb/web_sessions/`.
- Starting a run from the browser triggers the same real recon pipeline used by the CLI.
- Reports, event streams, and recon memory still live under the normal `~/.asrfacet_rb/output/` and `~/.asrfacet_rb/memory/` paths.
- The UI helps inspect sessions more easily, but it does not change the framework's authorization requirements or guarantee completeness.

## Session Persistence

Session drafts are stored under:

```text
~/.asrfacet_rb/web_sessions/
```

Design goals:

- atomic JSON writes
- safe autosave
- explicit save control
- accidental-close protection
- interrupted-run recovery

## Save And Close Behavior

- Draft changes mark the session as dirty.
- The browser prompts before the page closes if the draft is dirty or a run is active.
- Switching sessions now asks the operator to save before switching and will stay on the current session if they cancel.

## Recovery Behavior

Running sessions store a heartbeat. On restart:

- recent heartbeats are preserved as active state
- stale running sessions are marked `interrupted`
- the session event log records that recovery happened after an unclean stop

This helps the dashboard survive process crashes and power interruptions without silently losing operator context.

## Report Access

Completed sessions expose links for:

- CLI report
- TXT report
- HTML report
- JSON report

These are served from the stored artifact bundle on disk and remain available after the run completes.

## Health And Reachability

- Web health: `GET /healthz`
- Web readiness: `GET /readyz`
- Deploy manifest: `~/.asrfacet_rb/runtime/deploy.json`

If you start the stack with `asrfacet-rb deploy`, the command waits until the web control panel is reachable and then prints the exact URLs to use.
