# Getting Started

## Requirements

- Ruby `>= 3.2`
- Bundler
- A system you own or have explicit written permission to test

## Install For Development

```bash
bundle install
bundle exec ruby bin/asrfacet-rb help
```

## Install As A Local Application

ASRFacet-Rb ships with platform installers under `install/`.

- `install/windows.ps1`
- `install/linux.sh`
- `install/macos.sh`

Each installer supports:

- `install`
- `test`
- `uninstall`
- `update`

They stage the framework into its own `asrfacet-rb` application directory, install dependencies into that directory, create a launcher, and print the final install and report paths when complete.

## First Commands

```bash
bundle exec ruby bin/asrfacet-rb scan example.com
bundle exec ruby bin/asrfacet-rb passive example.com
bundle exec ruby bin/asrfacet-rb dns example.com
bundle exec ruby bin/asrfacet-rb ports 192.0.2.10 --ports 22,80,443
bundle exec ruby bin/asrfacet-rb --console
bundle exec ruby bin/asrfacet-rb --web-session
```

## Recommended First Scan

Start with a bounded run:

```bash
bundle exec ruby bin/asrfacet-rb scan example.com \
  --scope example.com,*.example.com \
  --exclude dev.example.com \
  --threads 50 \
  --ports top100 \
  --monitor \
  --memory \
  --format html
```

Why this profile is a good baseline:

- `--scope` keeps active validation inside the authorized boundary.
- `--exclude` prevents touching known sensitive or inherited hosts.
- `--threads 50` is a stable starting point for mixed discovery.
- `--ports top100` keeps network validation focused for a first pass.
- `--monitor` and `--memory` make repeat scans more useful immediately.
- `--format html` creates a shareable offline report bundle.

## Where Results Go

By default, every run stores a report bundle under:

```text
~/.asrfacet_rb/output/reports/<target>/<timestamp>/
```

Typical bundle contents:

- `report.cli.txt`
- `report.txt`
- `report.html`
- `report.json`

The pipeline may also write a JSONL event stream under:

```text
~/.asrfacet_rb/output/streams/
```

## Built-In Help

```bash
asrfacet-rb help
asrfacet-rb help scan
asrfacet-rb explain scope
asrfacet-rb manual
asrfacet-rb manual workflow
```
