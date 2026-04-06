# ASRFacet-Rb

ASRFacet-Rb is a Ruby 3.2+ attack surface reconnaissance toolkit for authorized security testing. It combines passive discovery, active validation, web fingerprinting, lightweight vulnerability hints, relationship mapping, and change tracking in a single offline-capable reporting pipeline.

## Features

- Passive subdomain collection across multiple sources
- DNS, certificate, WHOIS, ASN, HTTP, crawl, and vulnerability engines
- Knowledge graph pivoting, persistent recon memory, and change monitoring
- Asset scoring, JavaScript endpoint mining, and correlation analysis
- CLI, JSON, TXT, and offline HTML output modes

## Installation

```bash
bundle install
bundle exec ruby bin/asrfacet --help
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

MIT
