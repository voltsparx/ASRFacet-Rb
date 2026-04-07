# Publishing Notes

## First Release Readiness

This repository is prepared for an initial publish with emphasis on:

- bounded concurrency
- worker-level error isolation
- stage-level failure reporting
- persistent output bundles
- installer-based deployment
- local web control panel with persisted sessions
- built-in help, about, explain, manual, and offline reporting
- a safe local validation lab before real authorized targets

## Verification Performed

Verified in the repository before README refresh:

- `bundle exec rspec`
- `ruby -c` on the touched CLI and web-session files
- `ruby bin/asrfacet-rb help`

Latest verified suite result:

- `36 examples, 0 failures`

## Release Checklist

- Confirm `README.md` matches the current tested behavior.
- Confirm `docs/` links are valid.
- Confirm the installer scripts still support `install`, `test`, `uninstall`, and `update`.
- Confirm the man page renders locally.
- Confirm `--web-session` respects `--web-host` and `--web-port`.
- Confirm `--about` and `--explain` work in command and flag form.
- Confirm `lab` starts and serves the placeholder validation routes locally.
- Confirm report bundles are written to the configured output root.
- Confirm the license and repository metadata are correct.

## Suggested First Publish Scope

For a first public release, the strongest path is:

- stable CLI workflow
- stable web-session workflow
- offline HTML/TXT/JSON reporting
- documented install and output behavior
- explicit authorized-use language

Additional feature expansion can follow later once real operator feedback arrives.
