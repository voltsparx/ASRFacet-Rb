# `lib/asrfacet_rb/execution/`

This folder handles concurrency and engine orchestration support.

## Purpose

Execution components decide how work is queued, parallelized, timed, and
observed. They are responsible for keeping multi-engine runs stable under load.

## Components you will find here

- thread pools and worker coordination
- async and parallel execution helpers
- schedulers that record failures and stage outcomes

## Add code here when

- it manages how work runs
- it affects throughput, backpressure, retries, or stability
- it should be reusable by more than one scan stage
