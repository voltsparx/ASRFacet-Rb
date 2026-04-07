# `lib/asrfacet_rb/engines/`

This folder contains the scan and analysis engines used by the pipeline.

## Purpose

Each engine focuses on one discovery or validation concern, such as DNS, HTTP,
ports, crawling, certificate inspection, monitoring, or vulnerability
assessment. The pipeline composes these engines into a staged workflow.

## Design expectations

- keep engines focused on one job
- respect scope controls before active work
- fail safely and return structured results
- avoid owning cross-cutting concerns that belong in `core/` or `execution/`

## Related folders

- `../busters/` for wordlist-driven expansion
- `../passive/` for passive source collection
- `../execution/` for concurrency and scheduling support
