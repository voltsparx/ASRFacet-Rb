# `lib/asrfacet_rb/ui/`

This folder contains the operator-facing interfaces outside the web dashboard.

## Purpose

It owns the command-line experience, including:

- CLI command definitions
- interactive console behavior
- help, explain, about, and manual content
- onboarding and first-run guidance
- banner and terminal presentation helpers

## Use this folder when

- the feature changes how users interact in a terminal
- the feature improves discoverability or usability
- the logic should stay separate from scan execution internals
