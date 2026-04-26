# Changelog

## [2.1.0] - 2026-04-26

### Added
- Expanded the core error hierarchy with scan- and DNS-specific failures.
- Hardened the encrypted key store contract with machine-derived passphrases, PBKDF2, and dedicated CLI key management commands.
- Added deterministic spec coverage for the key store and per-source rate limiter.

### Changed
- Reworked the rate limiter to use thread-safe concurrent maps, per-source mutexes, and monotonic-clock throttling.
- Updated runtime dependency constraints for `caracal` and `hexapdf` to the requested support window.
- Refined passive-source and CLI error handling around the new `ASRFacet::Error` subclasses.

### Fixed
- Key-store decrypt failures now raise `ASRFacet::KeyStoreError`.
- CLI key management now reports keystore failures cleanly instead of surfacing raw exceptions.

## [2.0.0] - 2026

### Added
- Event-driven engine with EventBus, Dispatcher, PluginRegistry
- Drop-in plugin architecture (plugins/ directory)
- Per-source rate limiter (RateLimiter)
- Encrypted API key store (KeyStore) with CLI subcommands
- New passive sources: VirusTotal, URLScan.io, CommonCrawl, SecurityTrails
- Wordlist permutation engine (PermutationEngine)
- Live multi-stage progress dashboard (ProgressDashboard)
- `--dry-run` flag for scan command
- `--profile` flag (`cautious` / `balanced` / `deep`)
- SARIF 2.1.0 output
- Graph export: DOT, JSON, Mermaid (`graph` subcommand)
- Structured JSON logger (StructuredLogger)
- Proper error class hierarchy (`ASRFacet::Error` and subclasses)
- `concurrent-ruby` for thread-safe result storage and data structures
- Runtime dependency version constraints in the gemspec
- GitHub Actions CI pipeline updates for matrix verification and linting

### Changed
- ResultStore refactored to use concurrent collections while keeping the legacy category APIs
- `colorize` replaced with `pastel`
- Passive runner now supports key-backed and rate-limited v2 sources
- All new Ruby source files include `# frozen_string_literal: true`

### Fixed
- build:gem task now raises on silent failure
- ferrum added to Gemfile development group
- CLEAN glob anchored to `__dir__` in Rakefile
- ruby_exec uses `system` instead of the Rake DSL `sh`
- Web-session run/start and session persistence flow regressions

## [1.0.0] - 2026
- Initial release
