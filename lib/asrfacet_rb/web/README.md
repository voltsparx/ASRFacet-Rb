# `lib/asrfacet_rb/web/`

The web-session control panel is implemented here.

## Purpose

This folder powers the browser-based ASRFacet-Rb experience, including:

- the local web server
- session storage and recovery
- scan launch and live status tracking
- persistence for saved workspaces and report access

## Design intent

The web UI should remain local-first, resilient, and operator-friendly. Code in
this folder should preserve session safety, avoid accidental data loss, and
surface scan state clearly.
