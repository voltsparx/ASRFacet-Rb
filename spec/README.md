# `spec/`

This directory contains the automated test suite for ASRFacet-Rb.

## Purpose

Tests are organized to mirror the runtime layout so changes can be verified at
the subsystem level.

## Structure

- `core/`: shared primitives and safety behavior
- `engines/`: engine-level coverage
- `execution/`: worker, scheduler, and concurrency behavior
- `lab/`: local validation target behavior
- `passive/`: passive source runner behavior
- `output/`: report generation behavior
- `ui/`: CLI and console experience
- `web/`: web-session behavior and persistence

## Guidance

When adding a new subsystem or user-facing behavior, add or extend specs here
so release confidence stays high.

## Latest verified status

The current repository verification flow runs through `bundle exec rake`.
The latest verified RSpec result reflected in the repository is:

- `43 examples, 0 failures`
