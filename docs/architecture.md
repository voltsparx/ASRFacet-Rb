# Architecture

## High-Level Flow

ASRFacet-Rb runs an event-driven reconnaissance pipeline. Results from one stage feed the next stage through the internal store, graph, and event callbacks.

### Pipeline Stages

1. Passive reconnaissance
2. Recursive DNS and certificate discovery
3. Permutation and DNS busting
4. Discovery feedback loop
5. Port scanning
6. HTTP, crawl, JavaScript, and correlation
7. WHOIS and ASN enrichment
8. Vulnerability detection and monitoring

## Core Data Systems

### Result Store

`ASRFacet::ResultStore` collects deduplicated findings, hosts, ports, HTTP responses, crawl artifacts, findings, and summaries.

### Knowledge Graph

`ASRFacet::Core::KnowledgeGraph` stores relationships such as:

- domain -> subdomain
- subdomain -> IP
- host -> service
- IP -> ASN
- host -> finding

### Recon Memory

`ASRFacet::Core::ReconMemory` persists target history and supports:

- change tracking
- known-asset skipping
- repeat-run comparison

## Execution Layer

The execution layer lives under `lib/asrfacet_rb/execution/`.

### Thread Pool

`ASRFacet::Execution::ThreadPool` provides:

- fixed worker counts
- optional queue backpressure
- per-job timeout support
- completion, failure, and timeout counters
- structured worker error capture

This is the primary execution engine for I/O-heavy tasks.

### Scheduler

`ASRFacet::Execution::Scheduler` provides:

- stage timing
- stage timeout enforcement
- retry with backoff
- throttled execution
- execution history

The pipeline records scheduler output into the final payload so stage failures are visible instead of silently disappearing.

### Parallel Engine

`ASRFacet::Execution::ParallelEngine` is available for process-based or threaded batch work where tasks should be isolated and errors should be captured cleanly.

### Async Engine

`ASRFacet::Execution::AsyncEngine` supports cooperative concurrency when the optional async stack is present, with a safe fallback path when it is not.

## Resilience Controls

### Circuit Breakers

`ASRFacet::Core::CircuitBreaker` prevents repeatedly hammering unstable sources or hosts after repeated failure.

### Adaptive Rate Control

`ASRFacet::Core::AdaptiveRateController` watches HTTP response codes and increases or decreases delay to protect the operator from rate limits and reduce wasted work.

### Scope Enforcement

`ASRFacet::Core::ScopeEngine` is applied before active probing so the framework does not intentionally drift out of scope.

## Web Session Runtime

The local web UI uses:

- `ASRFacet::Web::SessionStore` for atomic session persistence
- `ASRFacet::Web::SessionRunner` for background runs
- `ASRFacet::Web::Server` for the local control panel

Session drafts survive accidental closes, and running sessions use heartbeats so stale runs can be recovered after interruption without falsely corrupting active state.
