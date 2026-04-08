# `test/`

This directory contains reusable verification scripts for ASRFacet-Rb.

## Purpose

These files let maintainers run quick release-style checks at any time without
having to remember a long set of manual commands.

## Main entry points

- `bundle exec rake`
- `bundle exec rake verify`
- `ruby test/run_all.rb`

## Targeted checks

- `bundle exec rake spec`: run the RSpec suite
- `bundle exec rake test:cli`: verify CLI entrypoints
- `bundle exec rake test:web`: verify web-session startup and routes
- `bundle exec rake test:lab`: verify the local validation lab
- `bundle exec rake test:install`: verify the installer flow for the current platform
- `bundle exec rake test:website_installers`: verify website-distributed installer assets and syntax checks

## Latest verified status

The current test harness is intended to back the publish workflow and the
README verification notes.

Latest verified repository result:

- `bundle exec rake` passed
- `52 examples, 0 failures`
- CLI, web-session, lab, installer, website-installer, and gem-build smoke checks all passed
