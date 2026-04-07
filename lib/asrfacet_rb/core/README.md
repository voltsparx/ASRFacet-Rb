# `lib/asrfacet_rb/core/`

Core framework primitives and guardrails live here.

## Purpose

This folder contains the low-level building blocks that multiple parts of
ASRFacet-Rb depend on, including:

- scope enforcement
- recon memory and persistence
- knowledge graph correlation
- circuit breaking and adaptive rate control
- thread-safe console/log helpers
- plugin registration and shared utility extensions

## Add code here when

- the logic is shared by more than one subsystem
- the feature is not tied to a specific engine or UI
- the code helps enforce safety, stability, or common behavior

## Avoid putting here

- engine-specific probing logic
- web-only UI behavior
- report formatting
