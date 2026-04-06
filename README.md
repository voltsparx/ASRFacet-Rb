# ASRFacet-Rb
**ASRFacet-Rb** is a Ruby 3.2+ attack surface reconnaissance toolkit designed for **authorized security testing**. <br>
It integrates passive discovery, active validation, web fingerprinting, lightweight vulnerability insights, relationship mapping, change tracking, and event-driven asset correlation into a unified, offline-capable pipeline.

<p align="center">
  <img src="https://raw.githubusercontent.com/voltsparx/ASRFacet-Rb/refs/heads/main/docs/images/illustration/asrfacet-rb-logo.png" alt="ASRFacet-Rb Logo" width="700">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.1.0-0A66C2?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/ruby-%3E%3D%203.2-red?style=for-the-badge&logo=ruby&logoColor=white" alt="Ruby >= 3.2">
  <img src="https://img.shields.io/badge/tests-165%2F165%20passing-2E8B57?style=for-the-badge" alt="Tests Passing">
  <img src="https://img.shields.io/badge/status-stable-4C956C?style=for-the-badge" alt="Status Stable">
  <img src="https://img.shields.io/badge/license-Proprietary-8B0000?style=for-the-badge" alt="License">
</p>

---

**ASRFacet-Rb** is a Ruby 3.2+ attack surface reconnaissance toolkit designed for **authorized security testing**.

It integrates passive discovery, active validation, web fingerprinting, lightweight vulnerability insights, relationship mapping, change tracking, and event-driven asset correlation into a unified, offline-capable pipeline.

---

## 🚀 Features

- Passive subdomain collection across multiple sources
- Recursive DNS, certificate, WHOIS, ASN, HTTP, and crawl analysis
- Knowledge graph pivoting, correlation analysis, and recon memory
- JavaScript endpoint mining, asset scoring, and monitoring diffs
- CLI, JSON, TXT, HTML, manual, and console-driven operator workflows
- JSONL event streaming for scan telemetry and recovery-oriented workflows

## Installation

```bash
bundle install
bundle exec ruby bin/asrfacet-rb --help
```

Manual page during development:

```bash
MANPATH="$PWD/man:$MANPATH" man asrfacet-rb
```

## Usage

```bash
bundle exec ruby bin/asrfacet-rb scan example.com
bundle exec ruby bin/asrfacet-rb passive example.com
bundle exec ruby bin/asrfacet-rb ports 127.0.0.1 --ports top100
bundle exec ruby bin/asrfacet-rb dns example.com
bundle exec ruby bin/asrfacet-rb interactive
bundle exec ruby bin/asrfacet-rb --console
bundle exec ruby bin/asrfacet-rb manual
```

Inside the console you can use:

```text
show commands
show options
show workflow
show config
show learning
info recon
man
wizard
```

## Configuration

User configuration is loaded from `~/.asrfacet_rb/config.yml` and deep-merged with `config/default.yml`.

Bundled wordlists live under `wordlists/`:

- `subdomains_small.txt`
- `subdomains_large.txt`
- `ports_top100.txt`
- `paths_common.txt`

Live scan telemetry is streamed to:

```text
output/streams/<target>.jsonl
```

Default configuration also includes resilience controls for circuit-breaker cooldowns on repeatedly failing modules.

## Output Formats

- `cli`
- `json`
- `txt`
- `html`

## Legal Disclaimer

ASRFacet-Rb is intended for authorized security testing only.

Only use this tool on systems you own or have explicit written permission to test. Unauthorized scanning may be illegal in your jurisdiction.

The author assumes no liability for misuse.

## License

Proprietary custom license. See `LICENSE`.