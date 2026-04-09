# Roadmap

This roadmap focuses on stability, clarity, and operator trust.

## Phase 1: Foundation Hardening (Now)

- Keep scheduler and engine boundaries strict.
- Expand smoke coverage for installer lifecycle behavior.
- Continue fault-isolation improvements and clearer operator-facing errors.
- Maintain publish gate at `bundle exec rake`.

## Phase 2: Intelligence Depth

- Expand correlation graph pivots for domain-IP-service-ASN traversals.
- Improve confidence scoring transparency in reports.
- Add more report-side guidance for triage sequencing.

## Phase 3: Scale and Performance

- Add stronger backpressure controls for very large wordlists and target sets.
- Improve queue telemetry and throughput visibility.
- Add tuned profiles for low-noise vs high-coverage recon plans.

## Phase 4: Operator Experience

- Improve web session dashboards for run comparison and drift review.
- Add richer built-in explain/manual topics tied to report artifacts.
- Improve first-run onboarding examples and scope-safety prompts.

## Long-Term Direction

Keep ASRFacet-Rb as a pipeline-based, offline-first, relationship-aware recon system instead of a one-shot scanner.
