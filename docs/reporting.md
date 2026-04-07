# Reporting Guide

## Output Strategy

Every completed run can produce multiple artifacts at once so the same scan is useful for:

- terminal review
- plain-text notes
- offline HTML sharing
- machine-readable automation
- event-stream debugging

## Default Report Bundle

By default, report bundles are written to:

```text
~/.asrfacet_rb/output/reports/<target>/<timestamp>/
```

Bundle contents:

- `report.cli.txt`
- `report.txt`
- `report.html`
- `report.json`

## Format Meanings

### CLI

Best for live operator review.

Includes:

- key counts
- important hosts
- ports
- findings
- artifact paths

### TXT

Best for notes, ticket attachments, or environments where HTML is inconvenient.

Includes:

- human-readable summaries
- explanation text
- recommendations
- change summaries

### HTML

Best for offline review and sharing.

Includes:

- summary tables
- top assets
- findings
- change summary
- graph-oriented sections
- offline charts and visual summaries

### JSON

Best for downstream tooling.

Includes:

- store contents
- graph
- diff
- correlations
- JS endpoint output
- execution metadata

### JSONL Stream

The live stream is useful for debugging or replaying a run timeline.

Default location:

```text
~/.asrfacet_rb/output/streams/
```

## How To Save A Specific Report

```bash
asrfacet-rb scan example.com --format html --output report.html
asrfacet-rb passive example.com --format json --output passive.json
```

Even when `--output` is used, the framework still writes the full stored report bundle unless the run fails before artifact generation completes.

## Reading Stored Reports After Install

After installation, operators can inspect prior artifacts directly under the output root:

```text
~/.asrfacet_rb/output/
```

The CLI prints the stored report paths after each run, and the web session UI exposes them as clickable report links for completed sessions.
