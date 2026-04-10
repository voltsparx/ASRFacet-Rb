# ASRFacet-Rb Website

This folder contains the static documentation website for ASRFacet-Rb.

## Purpose

The website is kept separate from the Ruby runtime so it can be:

- served by GitHub Pages
- maintained without touching application code
- validated independently in CI

## Structure

### Pages

- `index.html` is the docs homepage
- `getting-started.html` covers installation and first use
- `download.html` provides installer downloads
- `workflow.html` explains framework flow
- `cli-reference.html` documents commands and flags
- `modes.html` covers console, web, wizard, and lab usage
- `reporting.html` explains outputs and configuration
- `development.html` shows live GitHub development signals and raw file previews
- `project.html` covers author, repository, and license context

### CSS

- `css/core/` holds shared tokens and baseline styles
- `css/layout/` holds top bar, sidebar, content layout, and responsive rules
- `css/components/` holds reusable documentation UI pieces

### JavaScript

- `js/core/` holds shared data, state, and helper logic
- `js/features/` holds isolated interactive features
- `js/bootstrap/` holds the final page bootstrap

### Assets

- `web_assets/media/` holds icons, preview images, and website visuals
- `web_assets/installers/` holds downloadable installer scripts for the site

## Load Order

The HTML pages load CSS in this order:

1. `css/core/base.css`
2. `css/layout/topbar.css`
3. `css/layout/sidebar.css`
4. `css/layout/content.css`
5. `css/components/workflow.css`
6. `css/components/modules.css`
7. `css/components/development.css`
8. `css/layout/responsive.css`

The HTML pages load JavaScript in this order:

1. `js/core/site-data.js`
2. `js/core/helpers.js`
3. `js/features/sidebar.js`
4. `js/features/easter-eggs.js`
5. `js/features/search.js`
6. `js/features/contact-panel.js`
7. `js/features/workflow-visual.js`
8. `js/features/raw-popup.js`
9. `js/features/development-feed.js`
10. `js/bootstrap/app.js`

Do not change that order unless the dependency chain changes too.

## Maintenance Rules

- Keep the site fully static. No build step should be required for normal edits.
- Prefer extending the existing modules instead of creating duplicate behavior.
- Shared state belongs in `js/core/`.
- Page behavior belongs in `js/features/`.
- Final event wiring belongs in `js/bootstrap/app.js`.
- Shared design tokens belong in `css/core/base.css`.
- Put responsive overrides in `css/layout/responsive.css` unless a component truly needs isolated responsive behavior.
- Keep asset paths relative so GitHub Pages works without rewriting links.

## Verification

The GitHub workflows validate:

- workflow YAML syntax
- website asset presence
- website JS parse checks
- page include wiring

Local checks that match the workflow intent:

```powershell
node --check docs/website/js/core/site-data.js
node --check docs/website/js/core/helpers.js
node --check docs/website/js/features/sidebar.js
node --check docs/website/js/features/easter-eggs.js
node --check docs/website/js/features/search.js
node --check docs/website/js/features/contact-panel.js
node --check docs/website/js/features/workflow-visual.js
node --check docs/website/js/features/raw-popup.js
node --check docs/website/js/features/development-feed.js
node --check docs/website/js/bootstrap/app.js
```

## Notes

The root `docs/website/app.js` and `docs/website/styles.css` are kept only as
small legacy notes so the repository does not carry duplicate full bundles.
