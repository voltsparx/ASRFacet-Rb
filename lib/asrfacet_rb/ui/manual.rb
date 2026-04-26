# SPDX-License-Identifier: Proprietary
#
# ASRFacet-Rb: Attack Surface Reconnaissance Framework
# Copyright (c) 2026 voltsparx
#
# Author: voltsparx
# Repository: https://github.com/voltsparx/ASRFacet-Rb
# Contact: voltsparx@gmail.com
# License: See LICENSE file in the project root
#
# This file is part of ASRFacet-Rb and is subject to the terms
# and conditions defined in the LICENSE file.

module ASRFacet
  module UI
    module Manual
      SECTION_ORDER = %w[
        name
        synopsis
        description
        about
        commands
        console
        wizard
        local_lab
        deployment
        workflow
        recon_basics
        configurations
        outputs
        files
        transparency
        safety
        examples
      ].freeze

      SECTIONS = {
        "name" => {
          title: "NAME",
          body: [
            "asrfacet-rb, asrfrb - authorized attack surface reconnaissance and security mapping framework for Ruby 3.2+"
          ]
        },
        "synopsis" => {
          title: "SYNOPSIS",
          body: [
            "asrfacet-rb <command> [arguments] [options]",
            "asrfacet-rb --version",
            "asrfacet-rb --console",
            "asrfacet-rb --web-session",
            "asrfacet-rb manual [section]",
            "man asrfacet-rb",
            "man asrfrb"
          ]
        },
        "description" => {
          title: "DESCRIPTION",
          body: [
            "ASRFacet-Rb maps a target's external attack surface by combining passive discovery, active validation, service fingerprinting, lightweight finding generation, asset correlation, and change tracking.",
            "The framework is designed for systems you own or have explicit written permission to test. It emphasizes scope control, recon memory, and readable reporting so operators can understand what was discovered and why it matters.",
            "The console, manual, explain topics, and wizard are intentionally educational so new users can learn both the framework and the underlying reconnaissance concepts while they work."
          ]
        },
        "about" => {
          title: "ABOUT",
          body: [
            "ASRFacet-Rb is an operator-focused reconnaissance framework for Ruby 3.2+.",
            "It combines passive discovery, DNS and certificate enrichment, port and HTTP validation, JavaScript endpoint mining, reporting, and change tracking in one workflow.",
            "Operator interfaces include a one-shot CLI, a persistent console shell, a local browser-based session UI, offline reports, built-in explain topics, and a manual page.",
            "A safe local lab is also included so users can validate the framework on local placeholder surfaces before touching real authorized systems."
          ]
        },
        "commands" => {
          title: "COMMANDS",
          body: [
            "scan DOMAIN",
            "  Run the full reconnaissance pipeline. Aliases: s, sc.",
            "  This includes passive discovery, recursive DNS/certificate enrichment, active busting, port scanning, HTTP probing, crawl analysis, JavaScript endpoint mining, asset scoring, and vulnerability checks.",
            "passive DOMAIN",
            "  Run passive source aggregation only. Aliases: p, pa.",
            "  This is the lowest-noise way to inventory subdomains before active validation.",
            "ports HOST",
            "  Run a focused TCP scan against a host or IP. Aliases: pt, po.",
            "  Use this when you want a simpler scanner-engine connectivity pass without version or OS fingerprinting.",
            "portscan TARGET",
            "  Run the scanner engine directly with explicit scan type, timing, and optional fingerprinting.",
            "  Use this when you need control over SYN, UDP, ACK, FIN, NULL, XMAS, WINDOW, MAIMON, ping, or service detection behavior.",
            "  Raw-style TCP modes need a raw-capable TCP backend and elevated privileges.",
            "  ASRFacet-Rb can use Nping as that backend on Linux, macOS, and Windows. Use --raw-backend nping and --sudo when you want the CLI to relaunch itself with the needed privileges.",
            "dns DOMAIN",
            "  Collect DNS records and basic resolution data only. Aliases: d, dn.",
            "console",
            "  Launch the framework console. Aliases: c, con, shell.",
            "  This is the richest interface and is intended to feel like an operator shell.",
            "web",
            "  Launch the local web session control panel. Aliases: w, ui.",
            "  This provides saved sessions, live activity, report browsing, and crash-resistant drafts through a browser.",
            "lab",
            "  Launch the local validation lab with pre-built placeholder surfaces.",
            "  Use this to test scanning, crawling, reporting, and UI behavior against a local target before real authorized systems.",
            "deploy",
            "  Start the local web control plane and optional validation lab together in one command.",
            "  Deploy mode waits for readiness, prints health endpoints, and writes a manifest under ~/.asrfacet_rb/runtime/ by default.",
            "about",
            "  Print a framework overview and safety-oriented product summary.",
            "interactive",
            "  Launch the standalone guided workflow outside the console. Aliases: i, int.",
            "help [topic], explain TOPIC, manual [section]",
            "  Show self-documentation at different levels of depth.",
            "  Help aliases: h, ?. Explain aliases: x, exp. Manual aliases: m, man. Version aliases: v, ver."
          ]
        },
        "console" => {
          title: "CONSOLE",
          body: [
            "The console is the primary operator interface. It supports framework-style commands such as `show commands`, `show options`, `show workflow`, `show config`, `info recon`, `man`, and `wizard`.",
            "You can also run normal commands directly inside it, for example `scan example.com`, `passive example.com`, `dns example.com`, or `ports 192.0.2.10 --ports top1000`.",
            "For deeper connectivity work, run `portscan 192.0.2.10 --type syn --timing 4 --ports 1-1024 --version` directly from the console.",
            "Console-only helpers like `wizard`, `banner`, `about`, and `clear` exist to make the shell friendlier for first-time users."
          ]
        },
        "wizard" => {
          title: "WIZARD",
          body: [
            "The console wizard is a guided planner that asks what you are trying to learn, how careful you want to be, what kind of output you prefer, and whether you want monitoring or memory enabled.",
            "It then translates those answers into a concrete ASRFacet-Rb command, explains why the framework chose that profile, and can execute it for you immediately.",
            "Wizard mode is console-only so it can teach interactively without cluttering the normal CLI surface."
          ]
        },
        "local_lab" => {
          title: "LOCAL LAB",
          body: [
            "Use `asrfacet-rb lab` to launch a safe local validation target on 127.0.0.1 by default.",
            "The lab exposes placeholder discovery surfaces such as weak headers, permissive CORS, a directory-listing style page, JavaScript endpoint patterns, debug-style routes, and sanitized placeholder configuration files.",
            "Its purpose is to let you test crawling, reporting, explainability, and local web-session behavior before scanning a real authorized system."
          ]
        },
        "deployment" => {
          title: "DEPLOYMENT",
          body: [
            "Use `asrfacet-rb deploy` when you want the web control panel and the local validation lab to come up together in one process.",
            "The deploy stack performs readiness checks against both services, prints the operator URLs, and writes a runtime manifest to ~/.asrfacet_rb/runtime/deploy.json unless you override it.",
            "Use `--public` only when you intentionally want the services bound to 0.0.0.0 and reachable beyond the local machine."
          ]
        },
        "workflow" => {
          title: "WORKFLOW",
          body: [
            "1. Passive reconnaissance gathers known subdomains from external sources.",
            "2. Recursive DNS and certificate analysis validate hosts and expand the asset set.",
            "3. Permutation and DNS busting generate new candidate subdomains for active validation.",
            "4. The discovery loop feeds new assets back into DNS and certificate enrichment.",
            "5. Port scanning maps exposed network services.",
            "6. HTTP probing, crawling, and JavaScript analysis map the web attack surface.",
            "7. WHOIS and ASN enrichment provide ownership and infrastructure context.",
            "8. Vulnerability checks, monitoring, and scoring help prioritize what to inspect next."
          ]
        },
        "recon_basics" => {
          title: "RECON BASICS",
          body: [
            "Attack surface reconnaissance is the process of discovering every externally reachable asset that belongs to a target and understanding how those assets expose technology, data, or risk.",
            "Passive recon means using third-party knowledge without directly touching the target. Active recon means making requests or connections to the target to confirm what is really there.",
            "Good recon is iterative: you discover one asset, pivot through DNS or certificates, find related systems, validate them, and then rank the results so deeper testing focuses on the highest-value assets first.",
            "ASRFacet-Rb mirrors this process by combining passive collection, recursive enrichment, service mapping, HTTP fingerprinting, and change detection."
          ]
        },
        "configurations" => {
          title: "CONFIGURATIONS",
          body: [
            "Project defaults live in config/default.yml and user overrides live in ~/.asrfacet_rb/config.yml.",
            "Common settings include thread counts, timeouts, wordlist paths, output preferences, resilience tuning, and HTTP behavior such as retries, redirects, and SSL verification.",
            "Command-line flags override configuration values for a single run. This makes it easy to keep safe defaults while still customizing individual engagements."
          ]
        },
        "outputs" => {
          title: "OUTPUTS",
          body: [
            "cli",
            "  Terminal-friendly tables, live progress notes, and human-readable summaries for live triage.",
            "json",
            "  Machine-readable output for automation and downstream tooling.",
            "html",
            "  Offline report with findings, top targets, graph relationships, JavaScript coverage, tables, charts, explanations, and recommendations.",
            "pdf",
            "  Dark-theme printable report for review decks, evidence capture, and offline sharing.",
            "docx",
            "  Editable document export for formal reporting workflows.",
            "txt",
            "  Detailed plain-text export with summary, findings, explanations, recommendations, and stored artifact paths.",
            "csv",
            "  Flat exports for subdomains, IPs, ports, findings, and JavaScript endpoints.",
            "sarif",
            "  Structured security-tooling export for CI systems and downstream evidence pipelines.",
            "Automatic report bundle",
            "  Every run also stores CLI, TXT, HTML, and JSON reports under ~/.asrfacet_rb/output/reports/<target>/<timestamp>/ for later review, and direct scanner or web-session runs can additionally emit CSV, PDF, DOCX, SARIF, or all formats on request."
          ]
        },
        "files" => {
          title: "FILES",
          body: [
            "bin/asrfacet-rb",
            "  Primary executable.",
            "config/default.yml",
            "  Project default settings.",
            "~/.asrfacet_rb/config.yml",
            "  User configuration overrides.",
            "~/.asrfacet_rb/memory/",
            "  Per-target scan memory used for monitoring and delta analysis.",
            "wordlists/",
            "  Bundled seed lists for subdomains, ports, and common web paths.",
            "~/.asrfacet_rb/output/",
            "  Default report root for stored report bundles and JSONL event streams when no user override is configured.",
            "~/.asrfacet_rb/output/streams/",
            "  JSON-Lines event stream written during scans for recovery, auditing, and stateful recon workflows.",
            "~/.asrfacet_rb/output/reports/",
            "  Automatically stored CLI, TXT, HTML, and JSON reports grouped by target and timestamp.",
            "~/.asrfacet_rb/web_sessions/",
            "  Persistent web-session drafts, run state, and recovered sessions for the local control panel.",
            "man/asrfacet-rb.1",
            "  Manual page source for `man asrfacet-rb` on systems where the man page is installed or the repository man directory is on MANPATH.",
            "man/asrfrb.1",
            "  Alias man page source for `man asrfrb`."
          ]
        },
        "transparency" => {
          title: "TRANSPARENCY",
          body: [
            "Active modes make real DNS, TCP, HTTP, and related requests to the targets you configure.",
            "Passive results are lead generation, not guaranteed truth. They may include stale records, inherited infrastructure, or shared services that are not automatically authorized.",
            "The local web session starts a local HTTP server, stores drafts under ~/.asrfacet_rb/web_sessions/, and writes reports and streams to the normal output directories.",
            "Findings, scores, and recommendations are operator aids. They do not prove exploitability, ownership, or business impact on their own.",
            "ASRFacet-Rb does not claim stealth, evasion, or complete coverage. Operators must still define scope, exclusions, and verification steps explicitly."
          ]
        },
        "safety" => {
          title: "SAFETY",
          body: [
            "Only use this framework against systems you own or have explicit written permission to test.",
            "Use `--scope` and `--exclude` to make the authorized boundary explicit before active scanning.",
            "Prefer passive and cautious profiles when you are learning a target or when the authorization boundary is narrow.",
            "Never treat third-party or shared infrastructure as automatically in scope just because it appears in passive results."
          ]
        },
        "examples" => {
          title: "EXAMPLES",
          body: [
            "asrfacet-rb scan example.com --format html --output report.html",
            "asrfacet-rb passive example.com --format json --output passive.json",
            "asrfacet-rb ports api.example.com --ports 80,443,8443 --threads 50",
            "asrfacet-rb portscan 192.0.2.10 --type syn --timing 4 --ports 1-1024 --version",
            "asrfacet-rb lab --port 9393",
            "asrfacet-rb about",
            "asrfacet-rb --explain scope",
            "asrfacet-rb scan example.com --scope example.com,api.example.com --exclude dev.example.com --monitor",
            "asrfacet-rb --console",
            "man asrfacet-rb",
            "man asrfrb"
          ]
        }
      }.freeze

      ALIASES = {
        "overview" => "description",
        "about" => "about",
        "usage" => "synopsis",
        "config" => "configurations",
        "configuration" => "configurations",
        "output" => "outputs",
        "reporting" => "outputs",
        "lab" => "local_lab",
        "deploy" => "deployment",
        "deployment" => "deployment",
        "local_lab" => "local_lab",
        "recon" => "recon_basics",
        "basics" => "recon_basics",
        "learning" => "recon_basics",
        "how_it_works" => "workflow",
        "stages" => "workflow"
      }.freeze

      WIZARD_PROFILES = {
        "Cautious" => {
          description: "Favor low-noise, confirmation-first reconnaissance.",
          threads: 25,
          mode: "Passive",
          ports: "top100",
          monitor: false,
          memory: true,
          narrative: "Use this when you are still establishing the target boundary or want the safest first pass."
        },
        "Balanced" => {
          description: "Mix breadth and validation for a normal engagement baseline.",
          threads: 50,
          mode: "Full",
          ports: "top100",
          monitor: true,
          memory: true,
          narrative: "Use this for most authorized assessments where you want meaningful depth without pushing too hard."
        },
        "Deep" => {
          description: "Push further into service exposure and web enumeration.",
          threads: 100,
          mode: "Full",
          ports: "top1000",
          monitor: true,
          memory: false,
          narrative: "Use this when your authorization is broad and you want a stronger asset and service picture."
        }
      }.freeze

      module_function

      def plain_text(section = nil)
        if section.to_s.strip.empty?
          SECTION_ORDER.map { |key| render_section(key) }.join("\n\n")
        else
          key = normalize_section(section)
          return nil unless SECTIONS.key?(key)

          render_section(key)
        end
      rescue StandardError
        nil
      end

      def render_section(key)
        section = SECTIONS[key]
        lines = [section[:title]]
        Array(section[:body]).each { |line| lines << line }
        lines.join("\n")
      rescue StandardError
        ""
      end

      def normalize_section(section)
        key = section.to_s.strip.downcase.tr(" ", "_").tr("-", "_")
        ALIASES.fetch(key, key)
      rescue StandardError
        section.to_s.strip.downcase
      end

      def sections
        SECTION_ORDER.map { |key| [key, SECTIONS[key][:title]] }
      rescue StandardError
        []
      end
    end
  end
end
