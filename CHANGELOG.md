# Changelog

All notable changes to ASRFacet-Rb are documented in this file.

## [1.0.0] - 2026-04-09

### Added

- Pipeline-focused positioning in README and website home content.
- `VERSION` file for direct release signal visibility.
- `ROADMAP.md` for planned improvements and sequencing.
- Website trust-signal links to changelog, roadmap, and version.
- Website and README messaging around core idea, fit-check, and 30-second quick start.
- Reporting docs sample output section for CLI, JSON, and relationship mapping.

### Changed

- Website installer docs and UX framing to emphasize why the framework exists.
- Reporting verification text updated to latest verified run (`53 examples, 0 failures`).
- Recommendation logic in formatter improved so integrity remediation is shown only for warning/critical integrity states.

### Fixed

- Windows website installer CMD wrapper argument parsing stability.
- Windows website installer sparse-checkout argument handling and uninstall reliability.
- Windows website installer temp workspace path shortened to reduce path-length gem extraction failures.
- False integrity remediation recommendation for runs without integrity issues.
