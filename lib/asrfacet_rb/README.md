# `lib/asrfacet_rb/`

This is the main framework namespace for ASRFacet-Rb.

## Folder map

- `core/`: shared primitives such as scope control, memory, graphing, and safety helpers.
- `engines/`: active and passive analysis engines used by the pipeline.
- `busters/`: wordlist-driven discovery helpers.
- `execution/`: concurrency, scheduling, and worker coordination.
- `http/`: HTTP transport and retry logic.
- `passive/`: passive data sources and their runner.
- `output/`: report generation and change tracking.
- `ui/`: CLI, console, help, onboarding, and banner surfaces.
- `web/`: web-session dashboard, persistence, and runtime controller.
- `lab/`: local safe validation targets for testing the framework.
- `notifiers/`: outbound notifications such as webhooks.
- `mixins/`: small reusable modules shared across components.

## Purpose

If you are extending the framework, this is the directory to work in. Each
subfolder groups a specific responsibility so new features can be added without
mixing transport, scanning, UI, and reporting logic together.
