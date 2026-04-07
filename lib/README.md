# `lib/`

This directory contains the runtime code for ASRFacet-Rb.

## What lives here

- `asrfacet_rb.rb`: the main library entry point that wires dependencies together.
- `asrfacet_rb/`: the framework implementation, grouped by subsystem.

## Purpose

If you are trying to understand how the framework works internally, start here.
The code under this directory is what powers the CLI, web session mode, scan
pipeline, reporting, persistence, and execution layers.

## Where to go next

- See `lib/asrfacet_rb/README.md` for the internal package layout.
- See `docs/architecture.md` for the higher-level system view.
