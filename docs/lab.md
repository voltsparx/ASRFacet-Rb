# Local Lab

## Purpose

`asrfacet-rb lab` starts a safe local validation target so you can test the framework before using it on real authorized systems.

The local lab is intended for:

- command and report dry-runs
- crawler validation
- JavaScript endpoint discovery checks
- local web-session demonstrations
- first-use learning without touching external assets

## Launch

```bash
bundle exec ruby bin/asrfacet-rb lab
bundle exec ruby bin/asrfacet-rb lab --port 9393
```

Default bind:

- host: `127.0.0.1`
- port: `9292`

## What It Exposes

The lab includes placeholder discovery surfaces such as:

- a JavaScript-heavy page with API-looking routes
- a directory-listing style page
- permissive CORS on a sample API route
- debug-style status and metrics routes
- a sanitized placeholder `.env` download route
- an admin-style login form

The lab uses placeholder content only. It does not include live credentials or real secrets.

## Useful Paths

- `/`
- `/app`
- `/assets/app.js`
- `/browse/`
- `/admin`
- `/metrics`
- `/debug/status`
- `/download/.env`
- `/api/v1/users`
- `/graphql`
- `/rest/audit`
- `/cors/profile`

## Recommended Validation Flow

1. Start the lab.
2. Run `asrfacet-rb scan 127.0.0.1 --ports 9292 --format html`.
3. Open the saved HTML report and confirm the lab routes, JS endpoints, and report summaries appear as expected.
4. Repeat from the web session UI if you want to validate local browser-driven workflow behavior.
