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

### Central Deduplication

`ASRFacet::Core::Deduplicator` provides a single thread-safe fingerprint layer
for pipeline events and relationship writes so the same host, record, port, or
finding does not get processed repeatedly through different discovery paths.

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

### Execution Contract

ASRFacet-Rb keeps the execution boundary intentionally strict so concurrency
does not drift into multiple competing control systems.

- Scheduler decides
- Engines execute
- Investigators react
- Fusion layers store

In practical terms:

- `ASRFacet::Pipeline` is the orchestration owner for scan stages.
- `ASRFacet::Execution::Scheduler` owns retries, stage timing, throttling, and
  execution history.
- `ASRFacet::Execution::ThreadPool`, `ParallelEngine`, and `AsyncEngine` are
  execution adapters, not orchestrators.
- engines, busters, and passive sources must not create their own schedulers or
  stage-control loops.
- correlation, storage, and graph logic should consume results, not control
  work admission.

This boundary exists because overlapping control layers create failure modes
that are hard to reason about under load.

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

It is owned by an orchestrator, not by engines. The runtime contract rejects
engine-owned scheduler construction so execution ownership does not silently
blur over time.

The pipeline records scheduler output into the final payload so stage failures are visible instead of silently disappearing.

### Parallel Engine

`ASRFacet::Execution::ParallelEngine` is available for process-based or threaded batch work where tasks should be isolated and errors should be captured cleanly.

It should be treated as a worker primitive, not a second scheduler.

### Async Engine

`ASRFacet::Execution::AsyncEngine` supports cooperative concurrency when the optional async stack is present, with a safe fallback path when it is not.

It is an execution adapter only. It should not decide global retries, stage
ordering, or orchestration policy.

## Performance Posture

ASRFacet-Rb is optimized for operator workflow, correlation, reporting, and
bounded concurrent reconnaissance. It is tuned for observability, controlled
parallelism, and operator-guided attack-surface mapping rather than unbounded
raw-packet throughput.

That means the healthy performance posture is:

- use Ruby for orchestration, memory, reporting, and UI
- keep concurrency bounded and observable
- prefer streaming and incremental storage over large in-memory fanout
- use execution adapters as helpers, not as independent control planes
- treat very high-scale enumeration as a candidate for a future native
  acceleration layer rather than pretending Ruby has no ceiling

## Resilience Controls

### Circuit Breakers

`ASRFacet::Core::CircuitBreaker` prevents repeatedly hammering unstable sources or hosts after repeated failure.

### Adaptive Rate Control

`ASRFacet::Core::AdaptiveRateController` watches HTTP response codes and increases or decreases delay to protect the operator from rate limits and reduce wasted work.

### Scope Enforcement

`ASRFacet::Core::ScopeEngine` is applied before active probing so the framework does not intentionally drift out of scope.

### Event Backpressure

`ASRFacet::EventBus` uses a bounded internal queue and exposes queue stats so
producers cannot grow an invisible unbounded backlog without any signal.

### Graceful Shutdown

`ASRFacet::Pipeline` accepts a shutdown request, completes the current unit of
work, records why the run stopped, and returns the partial result bundle rather
than dropping progress on exit.

## Web Session Runtime

The local web UI uses:

- `ASRFacet::Web::SessionStore` for atomic session persistence
- `ASRFacet::Web::SessionRunner` for background runs
- `ASRFacet::Web::Server` for the local control panel

Session drafts survive accidental closes, and running sessions use heartbeats so stale runs can be recovered after interruption without falsely corrupting active state.

## Documentation Website Structure

The static documentation site under `docs/website/` is split into smaller
asset segments so it stays easy to maintain as pages grow.

### Website CSS

- `docs/website/css/core/` holds shared tokens and baseline styling.
- `docs/website/css/layout/` holds structural layout layers such as top bar,
  sidebar, page body, and responsive behavior.
- `docs/website/css/components/` holds reusable feature styling such as the
  workflow visual and documentation modules.

### Website JavaScript

- `docs/website/js/core/` holds shared website data, state, and helpers.
- `docs/website/js/features/` holds isolated UI features such as search,
  sidebar behavior, contact panel logic, easter eggs, and the workflow visual.
- `docs/website/js/bootstrap/` holds the final page bootstrap that wires the
  shared features together.

This keeps the docs site aligned with the same broader project principle used
elsewhere in ASRFacet-Rb: shared state first, focused modules second, and a
small bootstrap layer at the edge.

For maintenance details and exact website asset load order, see
`docs/website/README.md`.
