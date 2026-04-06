# ASRFacet-Rb

ASRFacet-Rb is a Ruby 3.2+ attack surface reconnaissance toolkit for authorized security testing. It combines passive discovery, active validation, web fingerprinting, lightweight vulnerability hints, relationship mapping, change tracking, and event-driven asset correlation in a single offline-capable pipeline.

## Features

- Passive subdomain collection across multiple sources
- Recursive DNS, certificate, WHOIS, ASN, HTTP, crawl, and vulnerability analysis
- Knowledge graph pivoting, persistent recon memory, monitoring, and change tracking
- Asset scoring, JavaScript endpoint mining, correlation analysis, and noise filtering
- CLI, JSON, TXT, and offline HTML output modes

## Installation

```bash
bundle install
bundle exec ruby bin/asrfacet --help
```

Compatibility shim:

```bash
bundle exec ruby bin/asrfacet-rb --help
```

## Usage

```bash
bundle exec ruby bin/asrfacet scan example.com
bundle exec ruby bin/asrfacet passive example.com
bundle exec ruby bin/asrfacet ports 127.0.0.1 --ports top100
bundle exec ruby bin/asrfacet interactive
```

## Configuration

User config is loaded from `~/.asrfacet_rb/config.yml` and deep-merged with `config/default.yml`.

## Output Formats

- `cli`
- `json`
- `txt`
- `html`

## Legal Disclaimer

ASRFacet-Rb is intended for authorized security testing only. Only use this tool on systems you own or have explicit written permission to test. Unauthorized scanning may be illegal in your jurisdiction. The author assumes no liability for misuse.

## License

Proprietary custom license. See `LICENSE`.
