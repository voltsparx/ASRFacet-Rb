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
    module HelpCatalog
      PRIMARY_EXECUTABLE = "asrfacet-rb".freeze

      TOPICS = {
        "scan" => {
          summary: "Run the full reconnaissance pipeline against a target domain.",
          usage: "asrfacet-rb scan DOMAIN [--ports top1000] [--wordlist WORDLIST] [--format cli|json|html|txt]",
          details: [
            "Use this when you want passive discovery, DNS enrichment, certificate analysis, port scanning, HTTP probing, and finding generation in one run.",
            "Add `--passive-only` when you want the scan command surface without active probing.",
            "Use `--scope` and `--exclude` together to keep active steps inside an explicit authorized boundary."
          ],
          examples: [
            "asrfacet-rb scan example.com",
            "asrfacet-rb scan example.com --ports top1000 --format html --output report.html",
            "asrfacet-rb scan example.com --scope example.com,api.example.com --exclude dev.example.com"
          ]
        },
        "passive" => {
          summary: "Collect subdomains from passive sources without active network probing.",
          usage: "asrfacet-rb passive DOMAIN [--format cli|json|html|txt]",
          details: [
            "Passive mode queries supported data sources and returns discovered hostnames plus any source errors.",
            "This is a good starting point when you need a lower-noise inventory before active validation."
          ],
          examples: [
            "asrfacet-rb passive example.com",
            "asrfacet-rb passive example.com --format json --output passive.json"
          ]
        },
        "ports" => {
          summary: "Run a focused TCP port scan against a host or IP.",
          usage: "asrfacet-rb ports HOST [--ports top100|top1000|1-1000|80,443]",
          details: [
            "Use this command when you only need network exposure and service banners.",
            "The port selector accepts named ranges, numeric ranges, or comma-separated custom lists."
          ],
          examples: [
            "asrfacet-rb ports 192.0.2.10",
            "asrfacet-rb ports app.example.com --ports 22,80,443,8080"
          ]
        },
        "dns" => {
          summary: "Collect DNS records for a domain without running the full pipeline.",
          usage: "asrfacet-rb dns DOMAIN [--format cli|json|html|txt]",
          details: [
            "DNS mode gathers record families such as A, AAAA, MX, NS, TXT, CNAME, and SOA.",
            "Use this when you want a fast inventory of naming and mail infrastructure."
          ],
          examples: [
            "asrfacet-rb dns example.com",
            "asrfacet-rb dns example.com --format json --output dns.json"
          ]
        },
        "interactive" => {
          summary: "Launch the guided wizard for beginners who prefer prompts over flags.",
          usage: "asrfacet-rb interactive",
          details: [
            "The interactive wizard walks through target, mode, ports, format, and optional API key setup step by step.",
            "Use `--console` or the `console` command when you want a persistent shell instead of a one-shot guided flow."
          ],
          examples: [
            "asrfacet-rb interactive"
          ]
        },
        "console" => {
          summary: "Open the persistent ASRFacet console shell.",
          usage: "asrfacet-rb --console",
          details: [
            "Console mode keeps you inside a friendly shell where you can run normal ASRFacet commands without leaving the session.",
            "Console-specific commands include `banner` to redraw the banner and `clear` to clear the screen.",
            "Use `help` or `explain TOPIC` inside the console to learn commands, flags, and workflows."
          ],
          examples: [
            "asrfacet-rb --console",
            "asrfacet-rb console"
          ]
        },
        "web-session" => {
          summary: "Launch the local web control panel with autosaved sessions and live activity.",
          usage: "asrfacet-rb --web-session [--web-host 127.0.0.1] [--web-port 4567]",
          details: [
            "Web session mode starts a local-only dashboard for recon planning, saved sessions, run history, report browsing, and live stage updates.",
            "Session drafts are autosaved to disk so configuration survives accidental browser closes, process crashes, and power loss.",
            "The dashboard uses the same pipeline, memory, monitoring, headless, webhook, and rate-control options as the CLI."
          ],
          examples: [
            "asrfacet-rb --web-session",
            "asrfacet-rb web --web-port 8080"
          ]
        },
        "output" => {
          summary: "Control where reports go and how they are rendered.",
          usage: "--format cli|json|html|txt and --output PATH",
          details: [
            "CLI output prints directly to the terminal and is best for quick inspection.",
            "JSON is best for scripting, HTML is best for sharing a styled offline report, and TXT is a plain-text export.",
            "ASRFacet-Rb also stores a full report bundle automatically under ~/.asrfacet_rb/output/reports/<target>/<timestamp>/ so installed users can find earlier runs easily.",
            "Use `--output` when you want an additional custom file path alongside the stored report bundle."
          ],
          examples: [
            "asrfacet-rb scan example.com --format html --output report.html",
            "asrfacet-rb passive example.com --format json --output passive.json"
          ]
        },
        "scope" => {
          summary: "Define additional allowed domains or IPs that remain in scope.",
          usage: "--scope target1,target2,target3",
          details: [
            "Scope rules are applied before active probing so the tool does not wander outside your authorized target list.",
            "Use this when your engagement covers more than the primary domain."
          ],
          examples: [
            "asrfacet-rb scan example.com --scope example.com,api.example.com,198.51.100.10"
          ]
        },
        "exclude" => {
          summary: "Block specific domains or IPs from being touched even if they are discovered.",
          usage: "--exclude target1,target2",
          details: [
            "Exclusions override allowed scope and prevent accidental probing of sensitive or third-party assets.",
            "This is especially useful when passive recon returns shared infrastructure or inherited hostnames."
          ],
          examples: [
            "asrfacet-rb scan example.com --exclude dev.example.com,203.0.113.9"
          ]
        },
        "monitor" => {
          summary: "Compare the current scan with stored recon memory and show what changed.",
          usage: "--monitor",
          details: [
            "Monitoring highlights newly seen subdomains, removed subdomains, new findings, and port changes.",
            "Use it when you run repeat scans and want a quick delta instead of reading the full report every time."
          ],
          examples: [
            "asrfacet-rb scan example.com --monitor"
          ]
        },
        "headless" => {
          summary: "Enable headless browser rendering for JavaScript-heavy applications.",
          usage: "--headless",
          details: [
            "Headless mode attempts to render Single Page Applications so client-side routes and network requests become visible.",
            "If Ferrum is not installed, the pipeline skips this step gracefully."
          ],
          examples: [
            "asrfacet-rb scan example.com --headless"
          ]
        },
        "webhook-url" => {
          summary: "Send real-time scan alerts to a webhook endpoint.",
          usage: "--webhook-url URL",
          details: [
            "Use this to forward high-severity findings and scan summaries to Slack or Discord during an authorized run.",
            "Notification failures never stop the scan."
          ],
          examples: [
            "asrfacet-rb scan example.com --webhook-url https://hooks.slack.com/services/...",
            "asrfacet-rb scan example.com --webhook-url https://discord.com/api/webhooks/... --webhook-platform discord"
          ]
        },
        "webhook-platform" => {
          summary: "Choose the webhook payload format for Slack or Discord.",
          usage: "--webhook-platform slack|discord",
          details: [
            "Use slack for Slack-compatible text payloads or discord for Discord webhook content payloads."
          ],
          examples: [
            "asrfacet-rb scan example.com --webhook-url https://discord.com/api/webhooks/... --webhook-platform discord"
          ]
        },
        "delay" => {
          summary: "Set the base request delay in milliseconds.",
          usage: "--delay MS",
          details: [
            "Use this when you want a steady pacing baseline before adaptive rate control reacts to 429 or 503 responses."
          ],
          examples: [
            "asrfacet-rb scan example.com --delay 250"
          ]
        },
        "adaptive-rate" => {
          summary: "Automatically slow down when a target starts rate limiting or struggling.",
          usage: "--adaptive-rate",
          details: [
            "Adaptive rate control increases delay after 429 or 503 responses and gradually speeds back up after stable responses."
          ],
          examples: [
            "asrfacet-rb scan example.com --adaptive-rate"
          ]
        },
        "memory" => {
          summary: "Reuse persistent recon memory to avoid rechecking already confirmed assets.",
          usage: "--memory",
          details: [
            "When enabled, ASRFacet can skip subdomains that were already confirmed in previous scans.",
            "Scan memory is stored per target under the user's home directory."
          ],
          examples: [
            "asrfacet-rb scan example.com --memory"
          ]
        },
        "top" => {
          summary: "Control how many top-ranked assets are shown in terminal output.",
          usage: "--top N",
          details: [
            "This affects CLI output by trimming the AssetScorer section to the N most interesting hosts.",
            "Use a larger number when you want broader triage visibility."
          ],
          examples: [
            "asrfacet-rb scan example.com --top 10"
          ]
        },
        "threads" => {
          summary: "Set worker concurrency for threaded engines.",
          usage: "--threads N",
          details: [
            "Higher values speed up scans but increase connection pressure and local resource usage.",
            "Reduce this on fragile targets or slower networks."
          ],
          examples: [
            "asrfacet-rb scan example.com --threads 50"
          ]
        },
        "timeout" => {
          summary: "Set the network timeout used by active operations.",
          usage: "--timeout SECONDS",
          details: [
            "Longer timeouts are more tolerant of slow services, while shorter values favor faster scans.",
            "Use this when you see intermittent nil responses from slow targets."
          ],
          examples: [
            "asrfacet-rb scan example.com --timeout 15"
          ]
        },
        "wordlist" => {
          summary: "Provide a custom wordlist for active busting phases.",
          usage: "--wordlist PATH",
          details: [
            "The wordlist is read lazily so large files remain memory-friendly.",
            "Use this to tailor DNS or directory discovery to the naming patterns you expect."
          ],
          examples: [
            "asrfacet-rb scan example.com --wordlist wordlists/subdomains.txt"
          ]
        },
        "shodan-key" => {
          summary: "Enable the Shodan passive source with your own API key.",
          usage: "--shodan-key KEY",
          details: [
            "The key is used only for the request and is not stored in results.",
            "Add it when you want Shodan-powered passive discovery included in source aggregation."
          ],
          examples: [
            "asrfacet-rb scan example.com --shodan-key YOUR_KEY",
            "asrfacet-rb passive example.com --shodan-key YOUR_KEY"
          ]
        },
        "passive-only" => {
          summary: "Run the scan command in passive mode without active probing.",
          usage: "asrfacet-rb scan DOMAIN --passive-only",
          details: [
            "This keeps the scan entry point but limits execution to passive source aggregation.",
            "Use it when you want the scan workflow without DNS busting, port scans, or HTTP requests."
          ],
          examples: [
            "asrfacet-rb scan example.com --passive-only"
          ]
        },
        "format" => {
          summary: "Choose the output renderer for reports.",
          usage: "--format cli|json|html|txt",
          details: [
            "CLI prints to the terminal, JSON is machine-friendly, HTML is an offline report, and TXT is a plain export.",
            "Pick the format based on whether you are triaging live, automating, or sharing the output."
          ],
          examples: [
            "asrfacet-rb scan example.com --format html",
            "asrfacet-rb dns example.com --format json"
          ]
        },
        "version" => {
          summary: "Print the currently installed ASRFacet-Rb version.",
          usage: "asrfacet-rb version",
          details: [
            "Use this when validating the local CLI version before running a scan or sharing results."
          ],
          examples: [
            "asrfacet-rb version"
          ]
        },
        "manual" => {
          summary: "Read the framework manual or a specific section.",
          usage: "asrfacet-rb manual [section]",
          details: [
            "Use the built-in manual when you want a structured reference for commands, workflow, configuration, outputs, and recon concepts.",
            "The same content also ships as a man page source under man/asrfacet-rb.1."
          ],
          examples: [
            "asrfacet-rb manual",
            "asrfacet-rb manual workflow",
            "man asrfacet-rb"
          ]
        },
        "wizard" => {
          summary: "Use the console-only guided planner that recommends a scan profile and command.",
          usage: "asrfacet-rb --console",
          details: [
            "Inside the console, run `wizard` to answer questions about your goal, scan depth, scope, and output preference.",
            "The wizard explains why it recommends each setting so beginners learn while configuring their run."
          ],
          examples: [
            "asrfacet-rb --console",
            "wizard"
          ]
        },
        "workflow" => {
          summary: "Understand the eight-stage reconnaissance pipeline.",
          usage: "asrfacet-rb manual workflow",
          details: [
            "Workflow covers passive recon, recursive enrichment, active validation, HTTP mapping, enrichment, monitoring, and scoring.",
            "Use this when you want to understand what the framework does at each stage and why those stages are ordered that way."
          ],
          examples: [
            "asrfacet-rb explain workflow",
            "asrfacet-rb manual workflow"
          ]
        },
        "recon" => {
          summary: "Learn the basics of attack surface reconnaissance.",
          usage: "asrfacet-rb manual recon_basics",
          details: [
            "This topic explains passive versus active recon, why pivoting matters, and how ASRFacet-Rb turns discovered assets into broader visibility.",
            "Use it when you want to understand the methodology, not just the flags."
          ],
          examples: [
            "asrfacet-rb explain recon",
            "asrfacet-rb manual recon_basics"
          ]
        },
        "configuration" => {
          summary: "Learn where defaults and user overrides live.",
          usage: "asrfacet-rb manual configurations",
          details: [
            "Configuration topics cover default.yml, user overrides, threads, timeouts, wordlists, and output defaults.",
            "Use this before customizing large or repeated scans."
          ],
          examples: [
            "asrfacet-rb explain configuration",
            "asrfacet-rb manual configurations"
          ]
        }
      }.freeze

      ALIASES = {
        "--scope" => "scope",
        "--exclude" => "exclude",
        "--monitor" => "monitor",
        "--headless" => "headless",
        "--webhook-url" => "webhook-url",
        "--webhook-platform" => "webhook-platform",
        "--delay" => "delay",
        "--adaptive-rate" => "adaptive-rate",
        "--memory" => "memory",
        "--top" => "top",
        "--threads" => "threads",
        "--timeout" => "timeout",
        "--wordlist" => "wordlist",
        "--shodan-key" => "shodan-key",
        "--passive-only" => "passive-only",
        "--format" => "format",
        "--output" => "output",
        "report" => "output",
        "reports" => "output",
        "s" => "scan",
        "sc" => "scan",
        "p" => "passive",
        "pa" => "passive",
        "pt" => "ports",
        "po" => "ports",
        "d" => "dns",
        "dn" => "dns",
        "i" => "interactive",
        "int" => "interactive",
        "c" => "console",
        "con" => "console",
        "w" => "web-session",
        "web" => "web-session",
        "ui" => "web-session",
        "x" => "explain",
        "exp" => "explain",
        "h" => "help",
        "?" => "help",
        "m" => "manual",
        "v" => "version",
        "ver" => "version",
        "shell" => "console",
        "guided" => "interactive",
        "man" => "manual",
        "attack-surface" => "recon",
        "config" => "configuration",
        "configurations" => "configuration"
      }.freeze

      module_function

      def menu(executable: PRIMARY_EXECUTABLE)
        [
          "ASRFacet-Rb Help",
          "",
          "Usage:",
          "  #{executable} <command> [arguments] [options]",
          "  #{executable} --console",
          "  #{executable} --web-session",
          "",
          "Commands:",
          "  scan DOMAIN        Full reconnaissance pipeline        Aliases: s, sc",
          "  passive DOMAIN     Passive subdomain discovery only    Aliases: p, pa",
          "  ports HOST         Focused TCP port scan               Aliases: pt, po",
          "  dns DOMAIN         DNS record collection only          Aliases: d, dn",
          "  interactive        Guided beginner workflow            Aliases: i, int",
          "  console            Persistent console shell            Aliases: c, con, shell",
          "  web                Local web control panel             Aliases: w, ui",
          "  explain TOPIC      Explain a command or topic          Aliases: x, exp",
          "  help [TOPIC]       Show the help menu                  Aliases: h, ?",
          "  manual [SECTION]   Read the built-in manual            Aliases: m, man",
          "  version            Print the installed version         Aliases: v, ver",
          "",
          "Global options:",
          "  -o, --output PATH  Save output to a file instead of printing",
          "  -f, --format TYPE  cli, json, html, or txt",
          "  -v, --verbose      Print stage-by-stage status messages",
          "  -t, --threads N    Worker concurrency for threaded engines",
          "      --timeout SEC  Network timeout for active requests",
          "      --scope LIST   Additional authorized domains or IPs",
          "      --exclude LIST Domains or IPs to never touch",
          "      --monitor      Show changes since the previous scan",
          "      --headless     Enable headless browser rendering for SPAs",
          "      --webhook-url  Send high-severity alerts to Slack or Discord",
          "      --webhook-platform NAME  slack or discord payload mode",
          "      --delay MS     Base delay between requests in milliseconds",
          "      --adaptive-rate Enable adaptive back-off on rate limiting",
          "      --web-session  Launch the local web session control panel",
          "      --web-host HOST Bind host for web session mode",
          "      --web-port N   Bind port for web session mode",
          "      --top N        Limit the printed Top Targets list",
          "      --memory       Skip already confirmed subdomains",
          "  -C, --console      Launch the persistent console shell",
          "",
          "Examples:",
          "  #{executable} scan example.com --ports top1000 --format html --output report.html",
          "  #{executable} passive example.com --format json",
          "  #{executable} ports api.example.com --ports 80,443,8443",
          "  #{executable} help scan",
          "  #{executable} explain scope",
          "  #{executable} --console",
          "  #{executable} --web-session",
          "",
          "Topics you can explain:",
          "  #{topics.sort.join(', ')}",
          "",
          "Note:",
          "  Use only on systems you own or have explicit written permission to test."
        ].join("\n")
      rescue StandardError
        "ASRFacet-Rb Help"
      end

      def explain(topic)
        entry = TOPICS[normalize(topic)]
        return nil if entry.nil?

        lines = []
        lines << entry_title(topic)
        lines << ""
        lines << "Summary:"
        lines << "  #{entry[:summary]}"
        lines << ""
        lines << "Usage:"
        lines << "  #{entry[:usage]}"
        if Array(entry[:details]).any?
          lines << ""
          lines << "Details:"
          Array(entry[:details]).each { |line| lines << "  - #{line}" }
        end
        if Array(entry[:examples]).any?
          lines << ""
          lines << "Examples:"
          Array(entry[:examples]).each { |line| lines << "  #{line}" }
        end
        lines.join("\n")
      rescue StandardError
        nil
      end

      def topics
        TOPICS.keys
      rescue StandardError
        []
      end

      def normalize(topic)
        raw = topic.to_s.strip.downcase
        return raw if TOPICS.key?(raw)

        cleaned = raw.gsub(/\Ahelp\s+/, "").gsub(/\Aexplain\s+/, "")
        cleaned = ALIASES.fetch(cleaned, cleaned)
        cleaned = cleaned.tr("_", "-")
        ALIASES.fetch(cleaned, cleaned)
      rescue StandardError
        topic.to_s.strip.downcase
      end

      def entry_title(topic)
        normalized = normalize(topic)
        "Explain: #{normalized}"
      rescue StandardError
        "Explain"
      end
    end
  end
end
