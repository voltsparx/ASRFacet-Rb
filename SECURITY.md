# Security Policy

## Scope

This document covers security issues in the ASRFacet-Rb framework itself.

It does not cover:

- findings discovered on targets scanned with the framework
- unauthorized use of the framework
- third-party service outages, bans, or API policy changes
- local environment issues outside the ASRFacet-Rb codebase

## Supported Versions

Security fixes are currently focused on the latest published release line and
the current `main` branch.

## Reporting A Vulnerability

Do not open a public GitHub issue for a security vulnerability in the
framework.

Report it privately to:

- `voltsparx@gmail.com`
- `voltsparx@proton.me`

Please include:

- affected version
- operating system and Ruby version
- a short impact summary
- clear reproduction steps
- proof-of-concept details if safe to share
- any suggested mitigation or workaround you found

## Response Expectations

- acknowledgement target: within 7 days
- follow-up status target: within 30 days when the report is valid and reproducible

Response time may vary depending on severity, reproducibility, and maintainer
availability.

## Safe Handling

- Share only the minimum material needed to reproduce the issue.
- Avoid including credentials, private keys, or unrelated sensitive data.
- If the issue can be triggered against a live target, reproduce it only in an
  environment you own or are explicitly authorized to test.

## Disclosure

Please wait for confirmation before public disclosure.

Once a fix, mitigation, or risk statement is ready, the project can coordinate
an appropriate public note through the normal repository release materials.
