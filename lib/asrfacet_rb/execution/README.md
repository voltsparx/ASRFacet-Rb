# `lib/asrfacet_rb/execution/`

This folder handles concurrency and engine orchestration support.

## Purpose

Execution components decide how work is queued, parallelized, timed, and
observed. They are responsible for keeping multi-engine runs stable under load.

## Components you will find here

- thread pools and worker coordination
- async and parallel execution helpers
- schedulers that record failures and stage outcomes

## Execution contract

This folder follows a strict ownership model:

- `Scheduler` decides
- execution helpers execute
- engines consume helpers but do not become orchestrators

The scheduler is owned by the orchestration layer, typically
`ASRFacet::Pipeline`. Engines, busters, and passive sources should not create
their own schedulers or competing control loops.

This keeps retries, throttling, stage timing, and failure reporting in one
place instead of spreading them across multiple overlapping systems.

## Add code here when

- it manages how work runs
- it affects throughput, backpressure, retries, or stability
- it should be reusable by more than one scan stage
