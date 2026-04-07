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

require "fileutils"
require "thor"
require "time"

module ASRFacet
  module UI
    class CLI < Thor
      default_task :help
      map %w[s sc] => :scan
      map %w[p pa] => :passive
      map %w[pt po] => :ports
      map %w[d dn] => :dns
      map %w[i int] => :interactive
      map %w[c con shell] => :console
      map %w[w web ui] => :web
      map %w[a] => :about
      map %w[h ?] => :help
      map %w[x exp] => :explain
      map %w[m man] => :manual
      map %w[v ver] => :version

      class_option :output, aliases: "-o", type: :string, desc: "Output file path"
      class_option :format, aliases: "-f", type: :string, default: "cli", enum: %w[cli json html txt], desc: "Output format"
      class_option :verbose, aliases: "-v", type: :boolean, default: false, desc: "Verbose output"
      class_option :threads, aliases: "-t", type: :numeric, default: 100, desc: "Worker count"
      class_option :timeout, type: :numeric, default: 10, desc: "Network timeout"
      class_option :scope, type: :string, desc: "Comma-separated allowed domains or IPs"
      class_option :exclude, type: :string, desc: "Comma-separated domains or IPs to exclude"
      class_option :monitor, type: :boolean, default: false, desc: "Show changes since the last scan"
      class_option :top, type: :numeric, default: 5, desc: "Top N scored assets to print"
      class_option :memory, type: :boolean, default: false, desc: "Skip subdomains already confirmed in previous scans"
      class_option :console, aliases: "-C", type: :boolean, default: false, desc: "Launch the interactive console shell"
      class_option :web_session, type: :boolean, default: false, desc: "Launch the local web session control panel"
      class_option :web_host, type: :string, default: "127.0.0.1", desc: "Bind host for web session mode"
      class_option :web_port, type: :numeric, default: 4567, desc: "Bind port for web session mode"
      class_option :headless, type: :boolean, default: false, desc: "Enable headless browser probing for SPAs"
      class_option :webhook_url, type: :string, desc: "Slack or Discord webhook URL for alerts"
      class_option :webhook_platform, type: :string, default: "slack", enum: %w[slack discord], desc: "Webhook platform"
      class_option :delay, type: :numeric, default: 0, desc: "Base delay between requests in milliseconds"
      class_option :adaptive_rate, type: :boolean, default: true, desc: "Enable adaptive rate control"

      class << self
        def start(given_args = ARGV, config = {})
          args = Array(given_args).dup
          ASRFacet::UI::FirstRunGuide.maybe_print(args)
          if args.delete("--console") || args.delete("-C")
            return super(["console", *args], config)
          end
          if args.delete("--web-session")
            return super(["web", *args], config)
          end
          if args.delete("--about")
            return super(["about", *args], config)
          end
          if (index = args.index("--explain"))
            topic = args[index + 1].to_s
            args.slice!(index, 2)
            return super(["explain", topic, *args], config)
          end

          super(args, config)
        rescue StandardError
          super(given_args, config)
        end
      end

      desc "scan DOMAIN", "Run a full reconnaissance pipeline"
      method_option :ports, aliases: "-p", type: :string, desc: "Port range (top100, top1000, 1-1000, 80,443)"
      method_option :passive_only, type: :boolean, default: false, desc: "Only run passive recon"
      method_option :wordlist, aliases: "-w", type: :string, desc: "Wordlist path"
      method_option :shodan_key, type: :string, desc: "Shodan API key"
      def scan(domain)
        result = if options[:passive_only]
                   passive_payload(domain)
                 else
                   ASRFacet::Pipeline.new(
                     domain,
                     build_options.merge(
                       stage_callback: method(:announce_stage),
                       event_callback: method(:announce_event)
                     )
                   ).run
                 end
        output_results(result, domain)
      rescue StandardError => e
        ASRFacet::Core::ThreadSafe.print_error(e.message)
      end

      desc "passive DOMAIN", "Run passive enumeration only"
      method_option :shodan_key, type: :string, desc: "Shodan API key"
      def passive(domain)
        output_results(passive_payload(domain), domain)
      rescue StandardError => e
        ASRFacet::Core::ThreadSafe.print_error(e.message)
      end

      desc "ports HOST", "Run a port scan only"
      method_option :ports, aliases: "-p", type: :string, desc: "Port range"
      def ports(host)
        store = ASRFacet::ResultStore.new
        ASRFacet::Core::ThreadSafe.print_status("Starting focused port discovery against #{host}") if options[:verbose]
        ASRFacet::Engines::PortEngine.new.scan(host, options[:ports] || "top100", workers: options[:threads]).each do |entry|
          store.add(:open_ports, entry)
          announce_event(:open_port, entry.merge(host: host)) if options[:verbose]
        end
        output_results({ store: store, top_assets: [], summary: store.summary }, host)
      rescue StandardError => e
        ASRFacet::Core::ThreadSafe.print_error(e.message)
      end

      desc "dns DOMAIN", "Run DNS collection only"
      def dns(domain)
        store = ASRFacet::ResultStore.new
        ASRFacet::Core::ThreadSafe.print_status("Collecting DNS records for #{domain}") if options[:verbose]
        dns_result = ASRFacet::Engines::DnsEngine.new.run(domain)
        dns_result[:data].each do |record_type, values|
          next if %i[wildcard wildcard_ips zone_transfer].include?(record_type)

          Array(values).each do |value|
            store.add(:dns, { host: domain, type: record_type, value: value })
            announce_event(:dns_record, { host: domain, type: record_type, value: value }) if options[:verbose]
          end
        end
        Array(dns_result[:data][:a]).each { |ip| store.add(:ips, ip) }
        Array(dns_result[:data][:aaaa]).each { |ip| store.add(:ips, ip) }
        output_results({ store: store, top_assets: [], summary: store.summary }, domain)
      rescue StandardError => e
        ASRFacet::Core::ThreadSafe.print_error(e.message)
      end

      desc "lab", "Launch the local validation lab with safe placeholder templates"
      method_option :host, type: :string, default: "127.0.0.1", desc: "Bind host for the local lab"
      method_option :port, type: :numeric, default: 9292, desc: "Bind port for the local lab"
      def lab
        ASRFacet::Lab::TemplateServer.new(
          host: options[:host],
          port: options[:port]
        ).start
      rescue StandardError => e
        ASRFacet::Core::ThreadSafe.print_error(e.message)
      end

      desc "interactive", "Launch the guided interactive interface"
      def interactive
        ASRFacet::UI::Interactive.new.start
      rescue StandardError => e
        ASRFacet::Core::ThreadSafe.print_error(e.message)
      end

      desc "console", "Launch the persistent interactive console shell"
      def console
        ASRFacet::UI::Console.new.start
      rescue StandardError => e
        ASRFacet::Core::ThreadSafe.print_error(e.message)
      end

      desc "web", "Launch the local web session control panel"
      def web
        ASRFacet::Web::Server.new(
          host: options[:web_host],
          port: options[:web_port]
        ).start
      rescue StandardError => e
        ASRFacet::Core::ThreadSafe.print_error(e.message)
      end

      desc "about", "Show a framework overview, usage guidance, and storage paths"
      def about
        puts(ASRFacet::UI::About.plain_text)
      rescue StandardError => e
        ASRFacet::Core::ThreadSafe.print_error(e.message)
      end

      desc "help [TOPIC]", "Show the main help menu or explain a specific topic"
      def help(topic = nil)
        if topic.to_s.strip.empty?
          puts(ASRFacet::UI::HelpCatalog.menu)
        else
          explain(topic)
        end
      rescue StandardError => e
        ASRFacet::Core::ThreadSafe.print_error(e.message)
      end

      desc "explain TOPIC", "Explain a command, flag, or workflow topic"
      def explain(topic)
        explanation = ASRFacet::UI::HelpCatalog.explain(topic)
        explanation ||= ASRFacet::UI::Manual.plain_text(topic)
        if explanation.to_s.empty?
          ASRFacet::Core::ThreadSafe.print_warning("No detailed help for `#{topic}`. Try `help` to see available topics.")
        else
          puts(explanation)
        end
      rescue StandardError => e
        ASRFacet::Core::ThreadSafe.print_error(e.message)
      end

      desc "manual [SECTION]", "Print the framework manual or a specific manual section"
      def manual(section = nil)
        text = ASRFacet::UI::Manual.plain_text(section)
        if text.to_s.empty?
          ASRFacet::Core::ThreadSafe.print_warning("No manual section for `#{section}`.")
        else
          puts(text)
        end
      rescue StandardError => e
        ASRFacet::Core::ThreadSafe.print_error(e.message)
      end

      desc "version", "Print the current version"
      def version
        puts(ASRFacet::VERSION)
      rescue StandardError
        nil
      end

      private

      def announce_stage(index, name, phase = :start, snapshot = {})
        return unless options[:verbose]

        if phase.to_sym == :start
          ASRFacet::Core::ThreadSafe.print_status("Stage #{index}/8 starting: #{name}")
        else
          ASRFacet::Core::ThreadSafe.print_good(
            "Stage #{index}/8 complete: #{name} | hosts=#{snapshot[:subdomains].to_i} ips=#{snapshot[:ips].to_i} ports=#{snapshot[:open_ports].to_i} web=#{snapshot[:http_responses].to_i} findings=#{snapshot[:findings].to_i}"
          )
        end
      rescue StandardError
        nil
      end

      def announce_event(event_type, data)
        return unless options[:verbose]

        entry = symbolize_keys(data)
        case event_type.to_sym
        when :subdomain
          ASRFacet::Core::ThreadSafe.print_good("Discovered host: #{entry[:host]}") unless entry[:host].to_s.empty?
        when :open_port
          ASRFacet::Core::ThreadSafe.print_good("Open port #{entry[:port]}/tcp on #{entry[:host]} #{entry[:service]}".strip)
        when :http_response
          status = entry[:status] || entry[:status_code]
          ASRFacet::Core::ThreadSafe.print_status("HTTP #{status} #{entry[:url] || entry[:host]}".strip)
        when :finding
          ASRFacet::Core::ThreadSafe.print_warning("Finding #{entry[:severity].to_s.upcase}: #{entry[:host]} - #{entry[:title]}")
        when :dns_record
          if %i[a aaaa cname mx ns].include?(entry[:type].to_sym)
            ASRFacet::Core::ThreadSafe.print_status("DNS #{entry[:type].to_s.upcase}: #{entry[:host]} -> #{entry[:value]}")
          end
        when :error
          ASRFacet::Core::ThreadSafe.print_warning("Engine note: #{entry[:engine]} - #{entry[:reason]}")
        end
      rescue StandardError
        nil
      end

      def build_options
        {
          ports: options[:ports],
          wordlist: options[:wordlist],
          threads: options[:threads],
          timeout: options[:timeout],
          crawl_depth: 2,
          crawl_pages: 100,
          api_keys: { shodan: options[:shodan_key] },
          scope: options[:scope],
          exclude: options[:exclude],
          monitor: options[:monitor],
          top: options[:top],
          memory: options[:memory],
          headless: options[:headless],
          webhook_url: options[:webhook_url],
          webhook_platform: options[:webhook_platform],
          delay: options[:delay],
          adaptive_rate: options[:adaptive_rate]
        }
      rescue StandardError
        {}
      end

      def passive_payload(domain)
        ASRFacet::Core::ThreadSafe.print_status("Starting passive discovery for #{domain}") if options[:verbose]
        store = ASRFacet::ResultStore.new
        result = ASRFacet::Passive::Runner.new(domain, build_options[:api_keys]).run
        store.add(:subdomains, domain)
        result[:subdomains].each do |subdomain|
          store.add(:subdomains, subdomain)
          announce_event(:subdomain, { host: subdomain }) if options[:verbose]
        end
        result[:errors].each { |error| store.add(:passive_errors, error) }
        { store: store, top_assets: [], summary: store.summary }
      rescue StandardError
        { store: ASRFacet::ResultStore.new, top_assets: [], summary: {} }
      end

      def output_results(result, domain)
        payload = normalize_payload(result)
        payload[:top_assets] = Array(payload[:top_assets]).first(top_limit)
        payload[:meta] = report_metadata(domain, payload)
        payload[:artifacts] = build_artifact_manifest(domain, payload[:meta][:generated_at], payload)
        save_report_bundle(payload)

        render_to_screen(payload)

        unless options[:output].to_s.empty?
          formatter_for(formatter_key).save(payload, options[:output])
          ASRFacet::Core::ThreadSafe.print_good("Saved requested #{formatter_key.upcase} report to #{options[:output]}")
        end

        print_monitoring(payload, domain) if options[:monitor]
        print_artifact_summary(payload[:artifacts])
      rescue StandardError => e
        ASRFacet::Core::ThreadSafe.print_error(e.message)
      end

      def render_to_screen(payload)
        if formatter_key == "cli" || interactive_terminal?
          puts(formatter_for("cli").format(payload))
          if formatter_key != "cli"
            ASRFacet::Core::ThreadSafe.print_status("Detailed #{formatter_key.upcase} output was written to the stored report bundle.")
          end
        else
          puts(formatter_for(formatter_key).format(payload))
        end
      rescue StandardError => e
        ASRFacet::Core::ThreadSafe.print_error(e.message)
      end

      def normalize_payload(result)
        return { store: result, top_assets: [] } unless result.is_a?(Hash)

        payload = result.dup
        payload[:store] ||= ASRFacet::ResultStore.new
        payload
      rescue StandardError
        { store: ASRFacet::ResultStore.new, top_assets: [] }
      end

      def formatter_for(key = formatter_key)
        case key.to_s.downcase
        when "json" then ASRFacet::Output::JsonFormatter.new
        when "html" then ASRFacet::Output::HtmlFormatter.new
        when "txt" then ASRFacet::Output::TxtFormatter.new
        else ASRFacet::Output::CliFormatter.new
        end
      rescue StandardError
        ASRFacet::Output::CliFormatter.new
      end

      def formatter_key
        options[:format].to_s.downcase
      rescue StandardError
        "cli"
      end

      def top_limit
        options[:top].to_i.positive? ? options[:top].to_i : 5
      rescue StandardError
        5
      end

      def print_monitoring(payload, domain)
        diff = payload[:diff]
        return if diff.nil? || diff.empty?

        tracker = ASRFacet::Output::ChangeTracker.new(domain)
        ASRFacet::Core::ThreadSafe.puts("")
        ASRFacet::Core::ThreadSafe.puts(tracker.format_cli(diff))
      rescue StandardError
        nil
      end

      def report_metadata(domain, payload)
        target = domain.to_s
        output_root = resolve_output_directory
        summary = payload[:summary]
        summary = payload[:store].summary if summary.nil? && payload[:store].respond_to?(:summary)
        {
          target: target,
          generated_at: Time.now.utc.iso8601,
          output_directory: output_root,
          stream_path: payload[:stream_path].to_s,
          summary: symbolize_keys(summary || {}),
          output_note: "Reports are automatically stored under the ASRFacet-Rb output directory for later review."
        }
      rescue StandardError
        { target: domain.to_s, generated_at: Time.now.utc.iso8601, output_directory: resolve_output_directory }
      end

      def build_artifact_manifest(domain, generated_at, payload)
        safe_target = safe_name(domain)
        stamp = generated_at.to_s.gsub(":", "-")
        report_dir = File.join(resolve_output_directory, "reports", safe_target, stamp)
        {
          report_directory: report_dir,
          cli_report: File.join(report_dir, "report.cli.txt"),
          txt_report: File.join(report_dir, "report.txt"),
          html_report: File.join(report_dir, "report.html"),
          json_report: File.join(report_dir, "report.json"),
          stream_report: payload[:stream_path].to_s
        }
      rescue StandardError
        {}
      end

      def save_report_bundle(payload)
        artifacts = symbolize_keys(payload[:artifacts] || {})
        report_dir = artifacts[:report_directory].to_s
        return if report_dir.empty?

        FileUtils.mkdir_p(report_dir)
        formatter_for("cli").save(payload, artifacts[:cli_report])
        formatter_for("txt").save(payload, artifacts[:txt_report])
        formatter_for("html").save(payload, artifacts[:html_report])
        formatter_for("json").save(payload, artifacts[:json_report])
      rescue StandardError
        nil
      end

      def print_artifact_summary(artifacts)
        paths = symbolize_keys(artifacts || {})
        return if paths.empty?

        ASRFacet::Core::ThreadSafe.print_good("Stored reports in #{paths[:report_directory]}")
        ASRFacet::Core::ThreadSafe.puts("  CLI:  #{paths[:cli_report]}") unless paths[:cli_report].to_s.empty?
        ASRFacet::Core::ThreadSafe.puts("  TXT:  #{paths[:txt_report]}") unless paths[:txt_report].to_s.empty?
        ASRFacet::Core::ThreadSafe.puts("  HTML: #{paths[:html_report]}") unless paths[:html_report].to_s.empty?
        ASRFacet::Core::ThreadSafe.puts("  JSON: #{paths[:json_report]}") unless paths[:json_report].to_s.empty?
        ASRFacet::Core::ThreadSafe.puts("  JSONL stream: #{paths[:stream_report]}") unless paths[:stream_report].to_s.empty?
      rescue StandardError
        nil
      end

      def resolve_output_directory
        File.expand_path((ASRFacet::Config.fetch("output", "directory") || "~/.asrfacet_rb/output").to_s)
      rescue StandardError
        File.expand_path("~/.asrfacet_rb/output")
      end

      def safe_name(value)
        cleaned = value.to_s.downcase.gsub(/[^a-z0-9.\-_]+/, "_")
        cleaned.empty? ? "scan" : cleaned.tr(".", "_")
      rescue StandardError
        "scan"
      end

      def interactive_terminal?
        $stdout.tty?
      rescue StandardError
        false
      end

      def symbolize_keys(value)
        case value
        when Hash
          value.each_with_object({}) do |(key, nested), memo|
            memo[key.to_sym] = symbolize_keys(nested)
          end
        when Array
          value.map { |entry| symbolize_keys(entry) }
        else
          value
        end
      rescue StandardError
        {}
      end
    end
  end
end
