# frozen_string_literal: true
# For use only on systems you own or have explicit
# written authorization to test.
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
require "json"
require "thor"
require "time"

module ASRFacet
  module UI
    class KeysCLI < Thor
      desc "set SOURCE VALUE", "Store an API key for a source"
      def set(source, value)
        key_store.set(source, value)
        puts "[ok] Key stored for: #{source}"
      rescue ASRFacet::KeyStoreError => e
        ASRFacet::Core::ThreadSafe.print_error(e.message)
      end

      desc "get SOURCE", "Retrieve an API key"
      def get(source)
        value = key_store.get(source)
        value ? puts(value) : puts("[!] No key found for: #{source}")
      rescue ASRFacet::KeyStoreError => e
        ASRFacet::Core::ThreadSafe.print_error(e.message)
      end

      desc "list", "List all stored source names"
      def list
        keys = key_store.list
        keys.empty? ? puts("[i] No keys stored yet") : keys.each { |key| puts("  #{key}") }
      rescue ASRFacet::KeyStoreError => e
        ASRFacet::Core::ThreadSafe.print_error(e.message)
      end

      desc "delete SOURCE", "Remove a stored key"
      def delete(source)
        key_store.delete(source)
        puts "[ok] Key removed for: #{source}"
      rescue ASRFacet::KeyStoreError => e
        ASRFacet::Core::ThreadSafe.print_error(e.message)
      end

      no_commands do
        def key_store
          ASRFacet::KeyStore.new
        end
      end
    end

    class GraphCLI < Thor
      desc "dot TARGET", "Export graph as Graphviz DOT"
      option :output, aliases: "-o", desc: "Output file path"
      def dot(target)
        out = ASRFacet::Graph::Exporter.new(ASRFacet::Core::KnowledgeGraph.load(target)).to_dot
        options[:output] ? File.write(options[:output], out) : puts(out)
      end

      desc "json TARGET", "Export graph as JSON nodes+edges"
      option :output, aliases: "-o", desc: "Output file path"
      def json(target)
        out = ASRFacet::Graph::Exporter.new(ASRFacet::Core::KnowledgeGraph.load(target)).to_json_graph
        options[:output] ? File.write(options[:output], out) : puts(out)
      end

      desc "mermaid TARGET", "Export graph as Mermaid diagram"
      option :output, aliases: "-o", desc: "Output file path"
      def mermaid(target)
        out = ASRFacet::Graph::Exporter.new(ASRFacet::Core::KnowledgeGraph.load(target)).to_mermaid
        options[:output] ? File.write(options[:output], out) : puts(out)
      end
    end

    class WorkspaceCLI < Thor
      desc "list", "List stored workspaces"
      def list
        workspaces = workspace_manager.list
        if workspaces.empty?
          puts "[i] No workspaces found"
          return
        end

        workspaces.each do |workspace|
          puts "#{workspace[:target]} | #{workspace[:status]} | last_active=#{workspace[:last_active]}"
        end
      rescue ASRFacet::Error => e
        ASRFacet::Core::ThreadSafe.print_error(e.message)
      end

      desc "show TARGET", "Show workspace session and graph metadata"
      def show(target)
        workspace = workspace_manager.load(target)
        return puts("[!] Workspace not found: #{target}") if workspace.nil?

        puts JSON.pretty_generate(workspace)
      rescue ASRFacet::Error => e
        ASRFacet::Core::ThreadSafe.print_error(e.message)
      end

      desc "delete TARGET", "Delete a workspace"
      def delete(target)
        if workspace_manager.delete(target)
          puts "[ok] Workspace deleted: #{target}"
        else
          puts "[!] Workspace not found: #{target}"
        end
      rescue ASRFacet::Error => e
        ASRFacet::Core::ThreadSafe.print_error(e.message)
      end

      desc "export TARGET", "Export a workspace as json or csv"
      option :format, type: :string, default: "json", enum: %w[json csv], desc: "Export format"
      def export(target)
        path = workspace_manager.export(target, format: export_format)
        puts path
      rescue ASRFacet::Error => e
        ASRFacet::Core::ThreadSafe.print_error(e.message)
      end

      no_commands do
        def workspace_manager
          ASRFacet::Intelligence::SessionManager.new
        end

        def export_format
          subcommand_format = options[:format].to_s
          inherited = parent_options.to_h
          inherited_format = (inherited[:format] || inherited["format"]).to_s
          return inherited_format if subcommand_format == "json" && %w[json csv].include?(inherited_format)

          subcommand_format
        rescue StandardError
          options[:format].to_s
        end
      end
    end

    class PluginsCLI < Thor
      class_option :mode, type: :string, desc: "Limit plugin catalog to one session mode"
      class_option :category, type: :string, desc: "Limit plugin catalog to one category"
      class_option :search, type: :string, desc: "Filter plugin catalog by free-text search"
      class_option :json, type: :boolean, default: false, desc: "Print JSON instead of an ASCII table"

      desc "list", "List built-in and user session plugins"
      def list
        entries = plugin_engine.catalog(mode: options[:mode], category: options[:category], search: options[:search])
        if options[:json]
          puts JSON.pretty_generate(entries)
          return
        end

        rows = entries.map do |entry|
          [entry[:name], entry[:category], Array(entry[:modes]).join(","), entry[:description]]
        end
        render_table(%w[Plugin Category Modes Description], rows)
        puts ""
        puts "Selection specifiers: #{ASRFacet::Extensions::AttachableCatalog.selector_help.join(', ')}"
      end

      desc "show NAME", "Show one plugin in detail"
      def show(name)
        entry = plugin_engine.find(name)
        return puts("[!] Plugin not found: #{name}") if entry.nil?

        puts JSON.pretty_generate(entry)
      end

      desc "resolve SPEC", "Resolve a plugin selection string against the current catalog"
      def resolve(spec)
        puts JSON.pretty_generate(plugin_engine.resolve(selection: spec, mode: options[:mode]).reject { |key, _value| key == :classes })
      end

      no_commands do
        def plugin_engine
          ASRFacet::Plugins::Engine.new(selection: "all")
        end

        def render_table(headers, rows)
          widths = headers.each_index.map do |index|
            ([headers[index].to_s.length] + rows.map { |row| row[index].to_s.length }).max
          end
          divider = "+" + widths.map { |width| "-" * (width + 2) }.join("+") + "+"
          puts divider
          puts "|" + headers.each_with_index.map { |value, index| " #{value.to_s.ljust(widths[index])} " }.join("|") + "|"
          puts divider
          rows.each do |row|
            puts "|" + row.each_with_index.map { |value, index| " #{value.to_s.ljust(widths[index])} " }.join("|") + "|"
          end
          puts divider
        end
      end
    end

    class FiltersCLI < Thor
      class_option :mode, type: :string, desc: "Limit filter catalog to one session mode"
      class_option :category, type: :string, desc: "Limit filter catalog to one category"
      class_option :search, type: :string, desc: "Filter filter catalog by free-text search"
      class_option :json, type: :boolean, default: false, desc: "Print JSON instead of an ASCII table"

      desc "list", "List built-in and user session filters"
      def list
        entries = filter_engine.catalog(mode: options[:mode], category: options[:category], search: options[:search])
        if options[:json]
          puts JSON.pretty_generate(entries)
          return
        end

        rows = entries.map do |entry|
          [entry[:name], entry[:category], Array(entry[:modes]).join(","), entry[:description]]
        end
        render_table(%w[Filter Category Modes Description], rows)
        puts ""
        puts "Selection specifiers: #{ASRFacet::Extensions::AttachableCatalog.selector_help.join(', ')}"
      end

      desc "show NAME", "Show one filter in detail"
      def show(name)
        entry = filter_engine.find(name)
        return puts("[!] Filter not found: #{name}") if entry.nil?

        puts JSON.pretty_generate(entry)
      end

      desc "resolve SPEC", "Resolve a filter selection string against the current catalog"
      def resolve(spec)
        puts JSON.pretty_generate(filter_engine.resolve(selection: spec, mode: options[:mode]).reject { |key, _value| key == :classes })
      end

      no_commands do
        def filter_engine
          ASRFacet::Filters::Engine.new(selection: "all")
        end

        def render_table(headers, rows)
          widths = headers.each_index.map do |index|
            ([headers[index].to_s.length] + rows.map { |row| row[index].to_s.length }).max
          end
          divider = "+" + widths.map { |width| "-" * (width + 2) }.join("+") + "+"
          puts divider
          puts "|" + headers.each_with_index.map { |value, index| " #{value.to_s.ljust(widths[index])} " }.join("|") + "|"
          puts divider
          rows.each do |row|
            puts "|" + row.each_with_index.map { |value, index| " #{value.to_s.ljust(widths[index])} " }.join("|") + "|"
          end
          puts divider
        end
      end
    end

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
      desc "keys SUBCOMMAND", "Manage encrypted API keys"
      subcommand "keys", KeysCLI
      desc "graph SUBCOMMAND", "Export the knowledge graph"
      subcommand "graph", GraphCLI
      desc "workspace SUBCOMMAND", "Manage intelligence workspaces"
      subcommand "workspace", WorkspaceCLI
      desc "plugins SUBCOMMAND", "Inspect pluggable session plugins"
      subcommand "plugins", PluginsCLI
      desc "filters SUBCOMMAND", "Inspect pluggable session filters"
      subcommand "filters", FiltersCLI

      class_option :output, aliases: "-o", type: :string, desc: "Output file path"
      class_option :format, aliases: "-f", type: :string, default: "cli", enum: %w[cli json html txt csv pdf docx all sarif], desc: "Output format"
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
      class_option :plugins, type: :string, desc: "Comma-separated session plugins or 'all'"
      class_option :filters, type: :string, desc: "Comma-separated session filters or 'all'"

      class << self
        def start(given_args = ARGV, config = {})
          args = Array(given_args).dup
          args = normalize_shortcuts(args)
          Thread.current[:asrfacet_rb_original_args] = args.dup
          ASRFacet::UI::FirstRunGuide.maybe_print(args)
          explicit_command = args.first.to_s.match?(/\A[^-]/)
          if !explicit_command && (args.delete("--console") || args.delete("-C"))
            return super(["console", *args], config)
          end
          if !explicit_command && args.delete("--web-session")
            return super(["web", *args], config)
          end
          if !explicit_command && args.delete("--about")
            return super(["about", *args], config)
          end
          if !explicit_command && args.delete("--version")
            return super(["version", *args], config)
          end
          if !explicit_command && (index = args.index("--explain"))
            topic = args[index + 1].to_s
            args.slice!(index, 2)
            return super(["explain", topic, *args], config)
          end

          super(args, config)
        rescue ASRFacet::Error
          super(given_args, config)
        end

        def normalize_shortcuts(args)
          normalized = Array(args).dup
          normalized = normalized.flat_map do |arg|
            case arg
            when "-ac-pa" then %w[--active --passive]
            else arg
            end
          end
          normalized
        rescue StandardError
          Array(args)
        end
      end

      desc "scan DOMAIN", "Run a full reconnaissance pipeline"
      method_option :ports, aliases: "-p", type: :string, desc: "Port range (top100, top1000, 1-1000, 80,443)"
      method_option :passive_only, type: :boolean, default: false, desc: "Only run passive recon"
      method_option :wordlist, aliases: "-w", type: :string, desc: "Wordlist path"
      method_option :shodan_key, type: :string, desc: "Shodan API key"
      method_option :dry_run, type: :boolean, default: false, aliases: "--dry-run", desc: "Show what would run without touching the network"
      method_option :profile, type: :string, desc: "Apply a named scan profile"
      def scan(domain)
        merged_options = build_scan_options
        if options[:dry_run]
          puts ASRFacet::DryRunPrinter.new(domain, merged_options.merge(output: options[:output], format: options[:format])).print
          return
        end

        return unless ensure_framework_ready!
        print_extension_review(:scan)

        result = if options[:passive_only]
                   passive_payload(domain)
                 else
                   dashboard = interactive_terminal? ? ASRFacet::ProgressDashboard.new : nil
                   pipeline = ASRFacet::Pipeline.new(
                     domain,
                     merged_options.merge(
                       stage_callback: lambda do |index, name, phase = :start, snapshot = {}|
                         announce_stage(index, name, phase, snapshot)
                         update_dashboard(dashboard, index, name, phase, snapshot)
                       end,
                       event_callback: method(:announce_event)
                     )
                   )
                   with_graceful_shutdown(pipeline) { pipeline.run }
                 end
        output_results(result, domain)
      rescue ASRFacet::Error => e
        report_exception("scan", e)
      end

      desc "passive DOMAIN", "Run passive enumeration only"
      method_option :shodan_key, type: :string, desc: "Shodan API key"
      def passive(domain)
        return unless ensure_framework_ready!
        print_extension_review(:passive)

        output_results(passive_payload(domain), domain)
      rescue ASRFacet::Error => e
        report_exception("passive", e)
      end

      desc "ports HOST", "Run a port scan only"
      method_option :ports, aliases: "-p", type: :string, desc: "Port range"
      def ports(host)
        return unless ensure_framework_ready!
        print_extension_review(:ports)

        scan_result = ASRFacet::Scanner::ScanEngine.new(
          scan_type: "connect",
          timing: 3,
          verbosity: options[:verbose] ? 1 : 0,
          version_detection: false,
          os_detection: false,
          version_intensity: 7,
          ports: options[:ports] || "top100"
        ).scan(host)
        output_results(ASRFacet::Scanner::ResultAdapter.to_payload(scan_result, target: host), host)
      rescue ASRFacet::Error => e
        report_exception("ports", e)
      end

      desc "portscan TARGET", "Run an ASRFacet-Rb connectivity and service scan"
      method_option :type, aliases: "-sS", type: :string, default: "connect", enum: %w[connect syn udp ack fin null xmas window maimon ping service], desc: "Scan type"
      method_option :timing, aliases: "-T", type: :numeric, default: 3, desc: "Timing template (0-5)"
      method_option :ports, aliases: "-p", type: :string, default: "top100", desc: "Port preset or explicit spec"
      method_option :version, aliases: "-sV", type: :boolean, default: false, desc: "Enable service version detection"
      method_option :os, aliases: "-O", type: :boolean, default: false, desc: "Enable OS detection"
      method_option :verbosity, aliases: "-v", type: :numeric, default: 0, desc: "Verbose level (0-3)"
      method_option :intensity, type: :numeric, default: 7, desc: "Version intensity (0-9)"
      method_option :raw_backend, type: :string, default: "auto", enum: %w[auto nping builtin], desc: "Raw TCP backend for raw-style scan types"
      method_option :sudo, aliases: %w[-E --elevate], type: :boolean, default: false, desc: "Attempt sudo or Administrator relaunch for raw-style scan types"
      def portscan(target)
        return unless ensure_framework_ready!
        print_extension_review(:portscan)

        terminal = scanner_terminal_output(scan_mode: :active)
        terminal.print_banner(
          target,
          options[:type].to_s,
          ASRFacet::Scanner::Timing.get(options[:timing]),
          :active,
          portscan_flags
        )

        tcp_prober = ASRFacet::Scanner::Probes::TCPProber.new(
          raw_adapter: scanner_raw_adapter(options[:raw_backend])
        )
        return if ASRFacet::Scanner::Privilege.maybe_relaunch!(
          scan_type: options[:type],
          tcp_prober: tcp_prober,
          argv: original_cli_args,
          requested: options[:sudo]
        )

        scan_result = ASRFacet::Scanner::ScanEngine.new(
          scan_type: options[:type],
          timing: options[:timing],
          verbosity: options[:verbosity],
          version_detection: options[:version],
          os_detection: options[:os],
          version_intensity: options[:intensity],
          ports: options[:ports],
          raw_backend: options[:raw_backend],
          tcp_prober: tcp_prober,
          terminal: terminal,
          result_store: ASRFacet::ResultStore.new,
          knowledge_graph: ASRFacet::Core::KnowledgeGraph.new,
          flags_used: portscan_flags
        ).scan(target)
        output_results(
          ASRFacet::Scanner::ResultAdapter.to_payload(scan_result, target: target).merge(
            terminal_mode: :portscan,
            terminal_output: terminal
          ),
          target
        )
      rescue ASRFacet::Error => e
        report_exception("portscan", e)
      end

      desc "enum TARGET", "Full enumeration - passive, active, or both"
      method_option :passive, aliases: ["-pa"], type: :boolean, default: false, desc: "Passive sources only"
      method_option :active, aliases: ["-ac"], type: :boolean, default: false, desc: "Active reconnaissance"
      method_option :brute, type: :boolean, default: false, desc: "Enable brute-force style DNS expansion"
      method_option :wordlist, aliases: "-w", type: :string, desc: "Wordlist path"
      method_option :portscan, type: :boolean, default: false, desc: "Include port scanning in active mode"
      method_option :scan_type, type: :string, default: "connect", enum: %w[connect syn udp ack fin null xmas window maimon ping service], desc: "Scan type for --portscan"
      method_option :timing, aliases: "-T", type: :numeric, default: 3, desc: "Timing template (0-5)"
      method_option :ports, aliases: "-p", type: :string, default: "top1000", desc: "Port preset or explicit spec"
      method_option :version, aliases: "-sV", type: :boolean, default: false, desc: "Enable service version detection"
      method_option :verbosity, aliases: "-v", type: :numeric, default: 0, desc: "Verbose level (0-3)"
      method_option :timeout, type: :numeric, desc: "Timeout in minutes"
      def enum(target)
        return unless ensure_framework_ready!

        modes = enum_modes
        print_extension_review(modes[:active] ? :enum : :passive)
        terminal = scanner_terminal_output(scan_mode: modes[:label])
        terminal.print_banner(target, "enumeration", ASRFacet::Scanner::Timing.get(options[:timing]), modes[:label], enum_flags)

        payload = if modes[:active] && modes[:passive]
                    run_combined_enum(target, terminal)
                  elsif modes[:active]
                    run_active_enum(target, terminal)
                  else
                    passive_payload(target).merge(meta: { mode: :passive, target: target })
                  end

        output_results(payload.merge(terminal_mode: :enum, terminal_output: terminal), target)
      rescue ASRFacet::Error => e
        report_exception("enum", e)
      end

      desc "intel TARGET", "Passive intelligence gathering only"
      method_option :sources, type: :string, desc: "Comma-separated source names"
      method_option :exclude_src, type: :string, desc: "Exclude source"
      method_option :timeout, type: :numeric, desc: "Timeout in minutes"
      method_option :verbosity, aliases: "-v", type: :numeric, default: 0, desc: "Verbose level (0-3)"
      def intel(target)
        return unless ensure_framework_ready!
        print_extension_review(:intel)

        terminal = scanner_terminal_output(scan_mode: :intel)
        terminal.print_banner(target, "intel", ASRFacet::Scanner::Timing.get(3), :intel, intel_flags)
        payload = passive_payload(target).merge(meta: { mode: :intel, target: target })
        output_results(payload.merge(terminal_mode: :intel, terminal_output: terminal), target)
      rescue ASRFacet::Error => e
        report_exception("intel", e)
      end

      desc "dns DOMAIN", "Run DNS collection only"
      def dns(domain)
        return unless ensure_framework_ready!

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
      rescue ASRFacet::Error => e
        report_exception("dns", e)
      end

      desc "track TARGET", "Diff the current workspace graph against the latest exported snapshot on or before a date"
      method_option :since, type: :string, desc: "Compare against the newest workspace export on or before this date"
      def track(target)
        workspace = load_asset_workspace(target)
        return if workspace.nil?

        current_graph = load_asset_graph(target)
        previous_graph = graph_snapshot_for(target, options[:since])
        diff = ASRFacet::Intelligence::Analysis::AssetDiffer.new.diff(previous_graph, current_graph)
        puts JSON.pretty_generate(diff)
      rescue ASRFacet::Error => e
        report_exception("track", e)
      end

      desc "viz TARGET", "Render a workspace graph as dot, json, or mermaid"
      method_option :format, aliases: "-f", type: :string, default: "json", enum: %w[dot json mermaid], desc: "Graph export format"
      method_option :output, aliases: "-o", type: :string, desc: "Output file path"
      def viz(target)
        workspace = load_asset_workspace(target)
        return if workspace.nil?

        graph = load_asset_graph(target)
        exporter = ASRFacet::Graph::Exporter.new(graph)
        body = case options[:format].to_s
               when "dot" then exporter.to_dot
               when "mermaid" then exporter.to_mermaid
               else exporter.to_json_graph
               end
        options[:output].to_s.empty? ? puts(body) : File.write(options[:output], body)
      rescue ASRFacet::Error => e
        report_exception("viz", e)
      end

      desc "subs TARGET", "List stored FQDN assets from a workspace"
      def subs(target)
        workspace = load_asset_workspace(target)
        return if workspace.nil?

        load_asset_graph(target).find_by_type(:fqdn).map(&:value).sort.each { |value| puts(value) }
      rescue ASRFacet::Error => e
        report_exception("subs", e)
      end

      desc "lab", "Launch the local validation lab with safe placeholder templates"
      method_option :host, type: :string, default: "127.0.0.1", desc: "Bind host for the local lab"
      method_option :port, type: :numeric, default: 9292, desc: "Bind port for the local lab"
      def lab
        return unless ensure_framework_ready!

        ASRFacet::Lab::TemplateServer.new(
          host: options[:host],
          port: options[:port]
        ).start
      rescue ASRFacet::Error => e
        report_exception("lab", e)
      end

      desc "deploy", "Start the web control panel and optional local lab in one go"
      method_option :public, type: :boolean, default: false, desc: "Bind services to 0.0.0.0 so they are reachable beyond localhost"
      method_option :with_lab, type: :boolean, default: true, desc: "Start the local validation lab alongside the web control panel"
      method_option :web_host, type: :string, default: "127.0.0.1", desc: "Bind host for the web control panel"
      method_option :web_port, type: :numeric, default: 4567, desc: "Bind port for the web control panel"
      method_option :lab_host, type: :string, default: "127.0.0.1", desc: "Bind host for the local lab"
      method_option :lab_port, type: :numeric, default: 9292, desc: "Bind port for the local lab"
      method_option :manifest, type: :string, desc: "Path to write the deployment manifest JSON"
      def deploy
        return unless ensure_framework_ready!

        ASRFacet::Deployment::Stack.new(
          public: options[:public],
          with_lab: options[:with_lab],
          web_host: options[:web_host],
          web_port: options[:web_port],
          lab_host: options[:lab_host],
          lab_port: options[:lab_port],
          manifest_path: options[:manifest]
        ).start
      rescue ASRFacet::Error => e
        report_exception("deploy", e)
      end

      desc "interactive", "Launch the guided interactive interface"
      def interactive
        return unless ensure_framework_ready!

        ASRFacet::UI::Interactive.new.start
      rescue ASRFacet::Error => e
        report_exception("interactive", e)
      end

      desc "console", "Launch the persistent interactive console shell"
      def console
        return unless ensure_framework_ready!

        ASRFacet::UI::Console.new.start
      rescue ASRFacet::Error => e
        report_exception("console", e)
      end

      desc "web", "Launch the local web session control panel"
      def web
        return unless ensure_framework_ready!

        ASRFacet::Web::Server.new(
          host: options[:web_host],
          port: options[:web_port]
        ).start
      rescue ASRFacet::Error => e
        report_exception("web", e)
      end

      desc "about", "Show a framework overview, usage guidance, and storage paths"
      def about
        puts(ASRFacet::UI::About.plain_text)
      rescue ASRFacet::Error => e
        ASRFacet::Core::ThreadSafe.print_error(e.message)
      end

      desc "help [TOPIC]", "Show the main help menu or explain a specific topic"
      def help(topic = nil)
        if topic.to_s.strip.empty?
          puts(ASRFacet::UI::HelpCatalog.menu)
        else
          explain(topic)
        end
      rescue ASRFacet::Error => e
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
      rescue ASRFacet::Error => e
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
      rescue ASRFacet::Error => e
        ASRFacet::Core::ThreadSafe.print_error(e.message)
      end

      desc "version", "Print the current version"
      def version
        puts(ASRFacet::VERSION)
      end

      private

      def workspace_manager
        @workspace_manager ||= ASRFacet::Intelligence::SessionManager.new
      end

      def original_cli_args
        Array(Thread.current[:asrfacet_rb_original_args]).dup
      rescue StandardError
        []
      end

      def scanner_raw_adapter(raw_backend)
        backend = raw_backend.to_s.downcase
        return nil if backend == "builtin"
        return ASRFacet::Scanner::Probes::NpingRawAdapter.new if %w[auto nping].include?(backend)

        nil
      rescue StandardError
        nil
      end

      def load_asset_workspace(target)
        workspace = workspace_manager.load(target)
        if workspace.nil?
          ASRFacet::Core::ThreadSafe.print_warning("Workspace not found: #{target}")
          return nil
        end

        workspace
      rescue ASRFacet::Error => e
        report_exception("workspace", e)
        nil
      end

      def load_asset_graph(target)
        ASRFacet::Intelligence::AssetGraph.new(target).load_from_disk
      end

      def graph_snapshot_for(target, since)
        path = workspace_snapshot_path(target, since)
        return { nodes: [], edges: [] } if path.nil?

        payload = JSON.parse(File.read(path), symbolize_names: true)
        payload[:graph] || { nodes: [], edges: [] }
      rescue JSON::ParserError => e
        raise ASRFacet::ParseError, "Unable to parse workspace export: #{e.message}"
      rescue Errno::EACCES, Errno::ENOENT, IOError, SystemCallError => e
        raise ASRFacet::Error, e.message
      end

      def workspace_snapshot_path(target, since)
        workspace = workspace_manager.load(target)
        return nil if workspace.nil?

        since_time = since.to_s.strip.empty? ? nil : Time.parse(since.to_s)
        candidates = Dir.glob(File.join(workspace[:workspace_path], "workspace_export_*.json"))
        return nil if candidates.empty?

        if since_time.nil?
          candidates.max_by { |path| File.mtime(path) }
        else
          candidates.select { |path| File.mtime(path) <= since_time }.max_by { |path| File.mtime(path) }
        end
      rescue ArgumentError => e
        raise ASRFacet::ParseError, "Invalid --since value: #{e.message}"
      end

      def announce_stage(index, name, phase = :start, snapshot = {})
        return unless options[:verbose]

        if phase.to_sym == :start
          ASRFacet::Core::ThreadSafe.print_status("Stage #{index}/8 starting: #{name}")
        else
          ASRFacet::Core::ThreadSafe.print_good(
            "Stage #{index}/8 complete: #{name} | hosts=#{snapshot[:subdomains].to_i} ips=#{snapshot[:ips].to_i} ports=#{snapshot[:open_ports].to_i} web=#{snapshot[:http_responses].to_i} findings=#{snapshot[:findings].to_i}"
          )
        end
      rescue ASRFacet::Error, IOError, NoMethodError, TypeError
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
      rescue ASRFacet::Error, IOError, NoMethodError, TypeError
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
          adaptive_rate: options[:adaptive_rate],
          plugins: options[:plugins],
          filters: options[:filters]
        }
      rescue ASRFacet::Error, NoMethodError, TypeError
        {}
      end

      def build_scan_options
        merged_options = build_options
        profile_name = options[:profile]
        return merged_options if profile_name.to_s.strip.empty?

        profile_defaults = {}
        %i[threads ports memory monitor timeout].each do |key|
          profile_defaults[key] = nil if option_uses_default?(:scan, key)
        end
        ASRFacet.apply_profile(profile_name, profile_defaults)
        profile_defaults.each do |key, value|
          merged_options[key] = value unless value.nil?
        end
        merged_options
      rescue ASRFacet::Error => e
        report_exception("profile", e)
        build_options
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
        { store: store, top_assets: [], summary: store.summary, meta: { target: domain.to_s, mode: :passive } }
      rescue ASRFacet::Error, NoMethodError, TypeError, ArgumentError
        { store: ASRFacet::ResultStore.new, top_assets: [], summary: {}, meta: { target: domain.to_s, mode: :passive } }
      end

      def output_results(result, domain)
        payload = normalize_payload(result)
        payload = apply_session_extensions(payload, domain)
        payload[:top_assets] = Array(payload[:top_assets]).first(top_limit)
        payload[:charts] = ASRFacet::Output::ChartDataBuilder.new(payload[:store]).build
        payload[:meta] = report_metadata(domain, payload)
        payload[:artifacts] = build_artifact_manifest(domain, payload[:meta][:generated_at], payload)
        save_report_bundle(payload)

        render_to_screen(payload)

        render_requested_output(payload, domain)

        print_monitoring(payload, domain) if options[:monitor]
        print_artifact_summary(payload[:artifacts])
      rescue ASRFacet::Error => e
        report_exception("output", e)
      end

      def render_to_screen(payload)
        if formatter_key == "cli" || router_format?(formatter_key) || formatter_key == "all" || interactive_terminal?
          if payload[:terminal_output] && (payload[:scan_result_object] || payload[:terminal_mode])
            payload[:terminal_output].print_scan_complete(payload[:scan_result_object], enum_result: payload)
          else
            puts(formatter_for("cli").format(payload))
          end
          if formatter_key != "cli" && !router_format?(formatter_key) && formatter_key != "all"
            ASRFacet::Core::ThreadSafe.print_status("Detailed #{formatter_key.upcase} output was written to the stored report bundle.")
          end
        else
          puts(formatter_for(formatter_key).format(payload))
        end
      rescue ASRFacet::Error => e
        report_exception("rendering", e)
      end

      def normalize_payload(result)
        return { store: result, top_assets: [] } unless result.is_a?(Hash)

        payload = result.dup
        payload[:store] ||= ASRFacet::ResultStore.new
        payload
      rescue ASRFacet::Error, NoMethodError, TypeError
        { store: ASRFacet::ResultStore.new, top_assets: [] }
      end

      def formatter_for(key = formatter_key)
        case key.to_s.downcase
        when "json" then ASRFacet::Output::JsonFormatter.new
        when "html" then ASRFacet::Output::HtmlFormatter.new
        when "txt" then ASRFacet::Output::TxtFormatter.new
        when "sarif" then ASRFacet::Output::SarifFormatter.new
        else ASRFacet::Output::CliFormatter.new
        end
      rescue ASRFacet::Error, NameError
        ASRFacet::Output::CliFormatter.new
      end

      def formatter_key
        options[:format].to_s.downcase
      rescue ASRFacet::Error, NoMethodError
        "cli"
      end

      def top_limit
        options[:top].to_i.positive? ? options[:top].to_i : 5
      rescue ASRFacet::Error, NoMethodError
        5
      end

      def print_monitoring(payload, domain)
        diff = payload[:diff]
        return if diff.nil? || diff.empty?

        tracker = ASRFacet::Output::ChangeTracker.new(domain)
        ASRFacet::Core::ThreadSafe.puts("")
        ASRFacet::Core::ThreadSafe.puts(tracker.format_cli(diff))
      rescue ASRFacet::Error, IOError, NoMethodError, TypeError
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
          output_note: "Reports are automatically stored under the ASRFacet-Rb output directory for later review.",
          plugins: selected_runtime_list(payload[:runtime_plugins], options[:plugins]),
          filters: selected_runtime_list(payload[:runtime_filters], options[:filters]),
          extension_resolution: symbolize_keys(payload[:extension_resolution] || {})
        }
      rescue ASRFacet::Error, NoMethodError, TypeError, ArgumentError
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
          csv_report_base: File.join(report_dir, "report.csv"),
          stream_report: payload[:stream_path].to_s
        }
      rescue ASRFacet::Error
        {}
      end

      def save_report_bundle(payload)
        artifacts = symbolize_keys(payload[:artifacts] || {})
        report_dir = artifacts[:report_directory].to_s
        return if report_dir.empty?

        FileUtils.mkdir_p(report_dir)
        formatter_for("cli").save(payload, artifacts[:cli_report])
        router = ASRFacet::Output::OutputRouter.new(
          payload[:store],
          payload.dig(:meta, :target).to_s,
          charts: payload[:charts] || {}
        )
        router.render("txt", artifacts[:txt_report])
        router.render("html", artifacts[:html_report])
        router.render("json", artifacts[:json_report])
      rescue ASRFacet::Error
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
      rescue ASRFacet::Error
        nil
      end

      def resolve_output_directory
        File.expand_path((ASRFacet::Config.fetch("output", "directory") || "~/.asrfacet_rb/output").to_s)
      rescue ASRFacet::Error, ArgumentError, IOError, NoMethodError
        File.expand_path("~/.asrfacet_rb/output")
      end

      def safe_name(value)
        cleaned = value.to_s.downcase.gsub(/[^a-z0-9.\-_]+/, "_")
        cleaned.empty? ? "scan" : cleaned.tr(".", "_")
      rescue ASRFacet::Error
        "scan"
      end

      def render_requested_output(payload, domain)
        key = formatter_key
        return if key == "cli"

        if router_format?(key) || key == "all"
          router = ASRFacet::Output::OutputRouter.new(
            payload[:store],
            domain,
            charts: payload[:charts] || {}
          )
          ASRFacet::Core::ThreadSafe.print_status("Rendering report (#{router.engine_info})...")
          if key == "all"
            output_dir = options[:output].to_s.empty? ? requested_output_directory(domain) : options[:output]
            router.render_all(output_dir)
            ASRFacet::Core::ThreadSafe.print_good("Saved requested reports to #{output_dir}")
          else
            path = options[:output].to_s.empty? ? requested_output_path(domain, key) : options[:output]
            router.render(key, path)
            ASRFacet::Core::ThreadSafe.print_good("Saved requested #{key.upcase} report to #{path}")
          end
        elsif !options[:output].to_s.empty?
          formatter_for(key).save(payload, options[:output])
          ASRFacet::Core::ThreadSafe.print_good("Saved requested #{key.upcase} report to #{options[:output]}")
        end
      rescue ASRFacet::Error => e
        report_exception("output_render", e)
      end

      def requested_output_directory(domain)
        File.join(Dir.pwd, "reports", safe_name(domain))
      rescue ASRFacet::Error
        File.join(Dir.pwd, "reports", "scan")
      end

      def requested_output_path(domain, format)
        base = requested_output_directory(domain)
        format = format.to_s.downcase
        extension = format == "csv" ? "csv" : format
        "#{base}.#{extension}"
      rescue ASRFacet::Error
        File.join(Dir.pwd, "reports", "scan.#{format}")
      end

      def router_format?(key)
        %w[txt html json csv pdf docx].include?(key.to_s.downcase)
      rescue ASRFacet::Error
        false
      end

      def update_dashboard(dashboard, index, _name, phase, snapshot)
        return if dashboard.nil?

        stage_index = index.to_i - 1
        if phase.to_sym == :start
          dashboard.start(stage_index)
        else
          dashboard.increment(stage_index, found: snapshot[:subdomains].to_i + snapshot[:open_ports].to_i + snapshot[:findings].to_i)
          dashboard.finish(stage_index)
        end
      rescue ASRFacet::Error, IOError, NoMethodError, TypeError
        nil
      end

      def option_uses_default?(task_name, option_name)
        task = self.class.tasks[task_name.to_s]
        return true if task.nil?

        definition = task.options[option_name.to_s]
        return true if definition.nil?

        options[option_name].to_s == definition.default.to_s
      rescue ASRFacet::Error, NoMethodError, TypeError
        true
      end

      def interactive_terminal?
        $stdout.tty?
      rescue IOError, NoMethodError
        false
      end

      def scanner_terminal_output(scan_mode:)
        ASRFacet::Scanner::TerminalOutput.new(
          verbosity: options[:verbosity] || (options[:verbose] ? 1 : 0),
          scan_mode: scan_mode
        )
      rescue StandardError
        ASRFacet::Scanner::TerminalOutput.new
      end

      def portscan_flags
        flags = []
        flags << "--type #{options[:type]}"
        flags << "-T#{options[:timing]}"
        flags << "-p #{options[:ports]}"
        flags << "--version" if options[:version]
        flags << "--os" if options[:os]
        flags << "--plugins #{options[:plugins]}" unless options[:plugins].to_s.empty?
        flags << "--filters #{options[:filters]}" unless options[:filters].to_s.empty?
        flags
      end

      def enum_flags
        flags = []
        flags << "--passive" if enum_modes[:passive]
        flags << "--active" if enum_modes[:active]
        flags << "--brute" if options[:brute]
        flags << "--portscan" if options[:portscan]
        flags << "--plugins #{options[:plugins]}" unless options[:plugins].to_s.empty?
        flags << "--filters #{options[:filters]}" unless options[:filters].to_s.empty?
        flags
      end

      def intel_flags
        flags = []
        flags << "--sources #{options[:sources]}" unless options[:sources].to_s.empty?
        flags << "--plugins #{options[:plugins]}" unless options[:plugins].to_s.empty?
        flags << "--filters #{options[:filters]}" unless options[:filters].to_s.empty?
        flags
      end

      def enum_modes
        passive = options[:passive] || !options[:active]
        active = options[:active]
        {
          passive: passive,
          active: active,
          label: if passive && active
                   :active_passive
                 elsif active
                   :active
                 else
                   :passive
                 end
        }
      end

      def run_active_enum(target, terminal)
        terminal.print_stage_start(1, "Active recon", 1)
        dashboard = interactive_terminal? ? ASRFacet::ProgressDashboard.new : nil
        pipeline = ASRFacet::Pipeline.new(
          target,
          build_scan_options.merge(
            stage_callback: lambda do |index, name, phase = :start, snapshot = {}|
              announce_stage(index, name, phase, snapshot)
              update_dashboard(dashboard, index, name, phase, snapshot)
            end,
            event_callback: method(:announce_event)
          )
        )
        with_graceful_shutdown(pipeline) do
          pipeline.run.merge(meta: { mode: :active, target: target }, terminal_output: terminal)
        end
      end

      def run_combined_enum(target, terminal)
        payload = run_active_enum(target, terminal)
        passive = passive_payload(target)
        merged_store = payload[:store] || ASRFacet::ResultStore.new
        Array(passive[:store].all(:subdomains)).each { |entry| merged_store.add(:subdomains, entry) }
        Array(passive[:store].all(:passive_errors)).each { |entry| merged_store.add(:passive_errors, entry) }
        payload.merge(store: merged_store, summary: merged_store.summary, meta: { mode: :active_passive, target: target })
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
      rescue ASRFacet::Error, NoMethodError, TypeError
        {}
      end

      def ensure_framework_ready!
        report = ASRFacet::Core::IntegrityChecker.check(output_root: resolve_output_directory)
        return true if report[:status].to_s == "ok"

        print_integrity_report(report)
        return true unless report[:status].to_s == "critical"

        ASRFacet::Core::ThreadSafe.print_error("Framework integrity check failed. The requested operation was not started.")
        false
      rescue ASRFacet::Error, NoMethodError, TypeError
        true
      end

      def print_integrity_report(report)
        status = report[:status].to_s
        printer = status == "critical" ? :print_error : :print_warning
        ASRFacet::Core::ThreadSafe.public_send(printer, report[:summary].to_s)
        Array(report[:issues]).each do |issue|
          ASRFacet::Core::ThreadSafe.puts("  - #{issue[:summary]}")
          ASRFacet::Core::ThreadSafe.puts("    Details: #{issue[:details]}") unless issue[:details].to_s.empty?
          ASRFacet::Core::ThreadSafe.puts("    Path: #{issue[:path]}") unless issue[:path].to_s.empty?
          ASRFacet::Core::ThreadSafe.puts("    Recommendation: #{issue[:recommendation]}") unless issue[:recommendation].to_s.empty?
        end
      rescue ASRFacet::Error, IOError, NoMethodError, TypeError
        nil
      end

      def report_exception(engine_name, error)
        failure = ASRFacet::Core::ErrorReporter.build(engine: engine_name, error: error, isolated: false)
        ASRFacet::Core::ThreadSafe.print_error(failure[:summary])
        ASRFacet::Core::ThreadSafe.puts("    Details: #{failure[:details]}") unless failure[:details].to_s.empty?
        ASRFacet::Core::ThreadSafe.puts("    Recommendation: #{failure[:recommendation]}") unless failure[:recommendation].to_s.empty?
      rescue ASRFacet::Error, IOError, NoMethodError, TypeError
        ASRFacet::Core::ThreadSafe.print_error(error.to_s)
      end

      def with_graceful_shutdown(pipeline)
        previous_handlers = {}
        %w[INT TERM].each do |signal|
          previous_handlers[signal] = Signal.trap(signal) do
            message = "#{signal} received. ASRFacet-Rb is stopping after the current operation and preserving partial results."
            ASRFacet::Core::ThreadSafe.print_warning(message)
            pipeline&.request_shutdown(message)
          end
        rescue ArgumentError, Errno::EINVAL, SystemCallError
          nil
        end
        yield
      ensure
        previous_handlers.each do |signal, handler|
          Signal.trap(signal, handler)
        rescue ArgumentError, Errno::EINVAL, SystemCallError
          nil
        end
      end

      def apply_session_extensions(payload, domain)
        return payload if payload[:extensions_applied] == true

        runtime = ASRFacet::Extensions::SessionAugmentor.new(logger: ASRFacet::Core::ThreadSafe).apply(
          target: domain,
          store: payload[:store],
          graph: payload[:graph],
          options: build_options,
          mode: payload.dig(:meta, :mode) || :scan,
          execution: payload[:execution] || {}
        )
        payload.merge(
          store: runtime[:store] || payload[:store],
          summary: runtime[:summary] || payload[:summary],
          runtime_plugins: Array(runtime[:plugin_trace]),
          runtime_filters: Array(runtime[:filter_trace]),
          extension_resolution: symbolize_keys(runtime[:extension_resolution] || {}),
          extensions_applied: true
        )
      rescue ASRFacet::Error, NoMethodError, TypeError
        payload
      end

      def selected_runtime_list(runtime_trace, option_value)
        trace = Array(runtime_trace).map { |entry| entry[:name].to_s }.reject(&:empty?)
        return trace unless trace.empty?

        value = option_value.to_s.strip
        return [] if value.empty?

        value.split(",").map(&:strip).reject(&:empty?)
      rescue ASRFacet::Error, NoMethodError, TypeError
        []
      end

      def print_extension_review(mode)
        return if options[:plugins].to_s.strip.empty? && options[:filters].to_s.strip.empty?

        plugin_plan = ASRFacet::Plugins::Engine.new(selection: options[:plugins]).resolve(mode: mode)
        filter_plan = ASRFacet::Filters::Engine.new(selection: options[:filters]).resolve(mode: mode)
        ASRFacet::Core::ThreadSafe.puts("")
        ASRFacet::Core::ThreadSafe.print_status("Resolved extension plan for #{mode}:")
        print_extension_line("Plugins", plugin_plan)
        print_extension_line("Filters", filter_plan)
        ASRFacet::Core::ThreadSafe.puts("")
      rescue ASRFacet::Error, IOError, NoMethodError, TypeError
        nil
      end

      def print_extension_line(label, plan)
        selected = Array(plan[:selected]).map { |entry| entry[:name].to_s }.reject(&:empty?)
        excluded = Array(plan[:excluded]).map { |entry| entry[:name].to_s }.reject(&:empty?)
        unknown = Array(plan[:unknown]).map(&:to_s).reject(&:empty?)
        ASRFacet::Core::ThreadSafe.puts("  #{label}: #{selected.empty? ? 'none' : selected.join(', ')}")
        ASRFacet::Core::ThreadSafe.puts("    Excluded: #{excluded.join(', ')}") unless excluded.empty?
        ASRFacet::Core::ThreadSafe.puts("    Unknown selectors: #{unknown.join(', ')}") unless unknown.empty?
      rescue ASRFacet::Error, IOError, NoMethodError, TypeError
        nil
      end
    end
  end
end
