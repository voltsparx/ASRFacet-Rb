# `install/`

Cross-platform installation and maintenance scripts live here.

## Purpose

This folder contains the scripts used to install ASRFacet-Rb like a normal
system tool on:

- Windows
- Linux
- macOS

After a successful system install, both `asrfacet-rb` and `asrfrb` are placed
on the user's command path as launchers for the same installed application.

## Supported modes

Each platform script supports the same lifecycle modes:

- `install`: install the application into its managed app directory
- `test`: stage a local install under the repository for validation
- `uninstall`: remove the managed install safely
- `update`: refresh the installed copy from the repository

## Notes

- these scripts are intended to manage ASRFacet-Rb-owned install locations
- they also set launch paths and related environment wiring for the platform
- `test-root/` is generated installer output and should not be treated as
  source code

## Verification

Installer smoke checks are wired into the repository-wide verification flow:

- `bundle exec rake test:install`

The latest verified install flow confirms that both `asrfacet-rb` and `asrfrb`
are created in the staged install and launch correctly as part of the current
`bundle exec rake` verification pass.
