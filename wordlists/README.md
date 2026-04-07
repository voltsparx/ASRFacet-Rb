# `wordlists/`

Bundled discovery dictionaries live here.

## Purpose

These files provide ready-to-use defaults for common discovery workflows such
as:

- subdomain expansion
- common web paths
- frequently checked ports

## Notes

- keep these lists practical and curated for operator use
- large lists should remain plain text and easy to replace
- code that consumes these files should prefer lazy iteration for memory safety

## Current bundled lists

- `subdomains_small.txt`
- `subdomains_large.txt`
- `paths_common.txt`
- `ports_top100.txt`
