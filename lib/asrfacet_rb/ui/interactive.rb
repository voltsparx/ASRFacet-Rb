# frozen_string_literal: true
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

require "tty-prompt"

module ASRFacet
  module UI
    class Interactive
      def initialize(prompt: TTY::Prompt.new)
        @prompt = prompt
      rescue StandardError
        @prompt = TTY::Prompt.new
      end

      def start
        target = @prompt.ask("Target domain:") { |q| q.required(true) }
        mode = @prompt.select("Scan mode:", ["Full", "Passive", "Ports", "DNS"])
        port_range = nil
        if %w[Full Ports].include?(mode)
          port_choice = @prompt.select("Port range:", ["Top100", "Top1000", "Custom"])
          port_range = port_choice == "Custom" ? @prompt.ask("Custom port range:") : port_choice.downcase
        end
        output_format = @prompt.select("Output format:", ["CLI", "JSON", "HTML", "TXT"]).downcase
        shodan_key = @prompt.yes?("Add a Shodan key?") ? @prompt.mask("Shodan API key:") : nil

        summary = [
          "Target: #{target}",
          "Mode: #{mode}",
          "Ports: #{port_range || 'n/a'}",
          "Format: #{output_format}",
          "Shodan: #{shodan_key.to_s.empty? ? 'no' : 'yes'}"
        ].join(" | ")
        return nil unless @prompt.yes?("Run scan? #{summary}")

        result = run_with_spinners(target, mode, port_range, shodan_key)
        render_output(result, output_format)
      rescue StandardError => e
        ASRFacet::Core::ThreadSafe.print_error(e.message)
        nil
      end

      private

      def run_with_spinners(target, mode, port_range, shodan_key)
        case mode
        when "Full"
          dashboard = ASRFacet::ProgressDashboard.new
          pipeline = ASRFacet::Pipeline.new(
            target,
            ports: port_range || "top100",
            api_keys: { shodan: shodan_key },
            stage_callback: lambda do |index, name, phase = :start, snapshot = {}|
              if phase.to_sym == :start
                dashboard.start(index - 1)
              else
                dashboard.increment(index - 1, found: snapshot[:subdomains].to_i + snapshot[:open_ports].to_i + snapshot[:findings].to_i)
                dashboard.finish(index - 1)
              end
            end
          )
          pipeline.run
        when "Passive"
          ASRFacet::Core::ThreadSafe.print_status("Running passive enumeration")
          store = ASRFacet::ResultStore.new
          result = ASRFacet::Passive::Runner.new(target, { shodan: shodan_key }).run
          store.add(:subdomains, target)
          result[:subdomains].each { |subdomain| store.add(:subdomains, subdomain) }
          result[:errors].each { |error| store.add(:passive_errors, error) }
          ASRFacet::Core::ThreadSafe.print_good("Passive enumeration complete")
          { store: store, top_assets: [] }
        when "Ports"
          ASRFacet::Core::ThreadSafe.print_status("Running port scan")
          store = ASRFacet::ResultStore.new
          ASRFacet::Engines::PortEngine.new.scan(target, port_range || "top100").each do |entry|
            store.add(:open_ports, entry)
          end
          ASRFacet::Core::ThreadSafe.print_good("Port scan complete")
          { store: store, top_assets: [] }
        else
          ASRFacet::Core::ThreadSafe.print_status("Collecting DNS records")
          store = ASRFacet::ResultStore.new
          dns_result = ASRFacet::Engines::DnsEngine.new.run(target)
          dns_result[:data].each do |record_type, values|
            next if %i[wildcard wildcard_ips zone_transfer].include?(record_type)

            Array(values).each { |value| store.add(:dns, { host: target, type: record_type, value: value }) }
          end
          ASRFacet::Core::ThreadSafe.print_good("DNS collection complete")
          { store: store, top_assets: [] }
        end
      rescue StandardError
        { store: ASRFacet::ResultStore.new, top_assets: [] }
      end

      def render_output(result, output_format)
        formatter = case output_format
                    when "json" then ASRFacet::Output::JsonFormatter.new
                    when "html" then ASRFacet::Output::HtmlFormatter.new
                    when "txt" then ASRFacet::Output::TxtFormatter.new
                    else ASRFacet::Output::CliFormatter.new
                    end

        if output_format == "cli"
          puts(formatter.format(result))
        else
          path = File.join(Dir.pwd, "asrfacet_report.#{output_format}")
          formatter.save(result, path)
          ASRFacet::Core::ThreadSafe.print_good("Saved report to #{path}")
        end
      rescue StandardError => e
        ASRFacet::Core::ThreadSafe.print_error(e.message)
      end
    end
  end
end
