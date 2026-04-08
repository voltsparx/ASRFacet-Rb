# `lib/asrfacet_rb/output/`

Reporting and result presentation live here.

## Purpose

This folder turns scan results into operator-friendly output formats and change
tracking artifacts.

## Contents

- human-readable CLI and TXT formatters
- HTML reporting for offline review
- JSON and JSONL export for tooling
- change tracking and result streaming helpers

## Use this folder for

- new report formats
- richer artifact summaries
- persistence-friendly output helpers

Do not place scan logic here; formatters should consume results, not generate
them.
