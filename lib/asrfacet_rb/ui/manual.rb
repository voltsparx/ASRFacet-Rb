# Part of ASRFacet-Rb — authorized testing only
module ASRFacet
  module UI
    module Manual
      SECTION_ORDER = %w[
        name
        synopsis
        description
        commands
        console
        wizard
        workflow
        recon_basics
        configurations
        outputs
        files
        safety
        examples
      ].freeze

      SECTIONS = {
        "name" => {
          title: "NAME",
          body: [
            "asrfacet-rb - authorized attack surface reconnaissance and security mapping framework for Ruby 3.2+"
          ]
        },
        "synopsis" => {
          title: "SYNOPSIS",
          body: [
            "asrfacet-rb <command> [arguments] [options]",
            "asrfacet-rb --console",
            "asrfacet-rb manual [section]",
            "man asrfacet-rb"
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
        "commands" => {
          title: "COMMANDS",
          body: [
            "scan DOMAIN",
            "  Run the full reconnaissance pipeline. This includes passive discovery, recursive DNS/certificate enrichment, active busting, port scanning, HTTP probing, crawl analysis, JavaScript endpoint mining, asset scoring, and vulnerability checks.",
            "passive DOMAIN",
            "  Run passive source aggregation only. This is the lowest-noise way to inventory subdomains before active validation.",
            "ports HOST",
            "  Run a focused TCP scan against a host or IP. Use this when you want network exposure without the full web workflow.",
            "dns DOMAIN",
            "  Collect DNS records and basic resolution data only.",
            "console",
            "  Launch the framework console. This is the richest interface and is intended to feel like an operator shell.",
            "interactive",
            "  Launch the standalone guided workflow outside the console.",
            "help [topic], explain TOPIC, manual [section]",
            "  Show self-documentation at different levels of depth."
          ]
        },
        "console" => {
          title: "CONSOLE",
          body: [
            "The console is the primary operator interface. It supports framework-style commands such as `show commands`, `show options`, `show workflow`, `show config`, `info recon`, `man`, and `wizard`.",
            "You can also run normal commands directly inside it, for example `scan example.com`, `passive example.com`, `dns example.com`, or `ports 192.0.2.10 --ports top1000`.",
            "Console-only helpers like `wizard`, `banner`, and `clear` exist to make the shell friendlier for first-time users."
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
            "Common settings include thread counts, timeouts, wordlist paths, output preferences, and HTTP behavior such as retries, redirects, and SSL verification.",
            "Command-line flags override configuration values for a single run. This makes it easy to keep safe defaults while still customizing individual engagements."
          ]
        },
        "outputs" => {
          title: "OUTPUTS",
          body: [
            "cli",
            "  Terminal-friendly tables and summaries for live triage.",
            "json",
            "  Machine-readable output for automation and downstream tooling.",
            "html",
            "  Offline report with findings, top targets, graph relationships, and JavaScript endpoint coverage.",
            "txt",
            "  Lightweight plain-text export."
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
            "man/asrfacet-rb.1",
            "  Manual page source for `man asrfacet-rb` on systems where the man page is installed or the repository man directory is on MANPATH."
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
            "asrfacet-rb scan example.com --scope example.com,api.example.com --exclude dev.example.com --monitor",
            "asrfacet-rb --console",
            "man asrfacet-rb"
          ]
        }
      }.freeze

      ALIASES = {
        "overview" => "description",
        "usage" => "synopsis",
        "config" => "configurations",
        "configuration" => "configurations",
        "output" => "outputs",
        "reporting" => "outputs",
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
