# `lib/asrfacet_rb/http/`

HTTP client and transport behavior lives here.

## Purpose

This folder provides the framework's network request layer, including:

- standard retry-aware HTTP requests
- adaptive rate handling hooks
- custom low-level transport for edge-case HTTP behavior

## Why this is separate

Keeping transport code isolated makes it easier to tune retries, headers,
timeouts, redirect handling, and fallback behavior without coupling that logic
to engines or UI code.
