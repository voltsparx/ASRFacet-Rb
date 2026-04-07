# Web Session Guide

## Launch

```bash
bundle exec ruby bin/asrfacet-rb --web-session
bundle exec ruby bin/asrfacet-rb --web-session --web-host 127.0.0.1 --web-port 4573
```

The web control panel is local-only by default and binds to `127.0.0.1:4567` unless overridden.

## What The Dashboard Does

- create and save named sessions
- configure scan mode and options
- launch runs from the browser
- watch stage-by-stage activity
- view run summaries and saved report links
- persist drafts across browser closes and host interruptions

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

## Themes

The dashboard ships with:

- Light
- Dark
- Grey

Theme selection is stored locally in the browser so the UI returns to the last operator preference.
