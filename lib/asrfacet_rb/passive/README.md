# `lib/asrfacet_rb/passive/`

Passive source integrations and their runner live here.

## Purpose

These sources collect data without directly probing the target service itself,
for example by querying public datasets or passive intelligence endpoints.

## Structure

- `base_source.rb`: shared source interface
- source adapters such as `crtsh`, `alienvault`, `wayback`, and others
- `runner.rb`: fan-out, aggregation, and source-level safety handling

## Expectations

- source classes should be easy to disable or extend
- failures should be isolated per source
- rate limits should not break the full scan
