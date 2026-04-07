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
require "tty-spinner"

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
          current_spinner = nil
          pipeline = ASRFacet::Pipeline.new(
            target,
            ports: port_range || "top100",
            api_keys: { shodan: shodan_key },
            stage_callback: lambda do |index, name|
              current_spinner&.success("Completed stage #{index - 1}") if index > 1
              current_spinner = TTY::Spinner.new("[:spinner] Stage #{index}/8 #{name}", format: :dots)
              current_spinner.auto_spin
            end
          )
          result = pipeline.run
          current_spinner&.success("Completed stage 8")
          result
        when "Passive"
          spinner = TTY::Spinner.new("[:spinner] Running passive enumeration", format: :dots)
          spinner.auto_spin
          store = ASRFacet::ResultStore.new
          result = ASRFacet::Passive::Runner.new(target, { shodan: shodan_key }).run
          store.add(:subdomains, target)
          result[:subdomains].each { |subdomain| store.add(:subdomains, subdomain) }
          result[:errors].each { |error| store.add(:passive_errors, error) }
          spinner.success("Passive enumeration complete")
          { store: store, top_assets: [] }
        when "Ports"
          spinner = TTY::Spinner.new("[:spinner] Running port scan", format: :dots)
          spinner.auto_spin
          store = ASRFacet::ResultStore.new
          ASRFacet::Engines::PortEngine.new.scan(target, port_range || "top100").each do |entry|
            store.add(:open_ports, entry)
          end
          spinner.success("Port scan complete")
          { store: store, top_assets: [] }
        else
          spinner = TTY::Spinner.new("[:spinner] Collecting DNS records", format: :dots)
          spinner.auto_spin
          store = ASRFacet::ResultStore.new
          dns_result = ASRFacet::Engines::DnsEngine.new.run(target)
          dns_result[:data].each do |record_type, values|
            next if %i[wildcard wildcard_ips zone_transfer].include?(record_type)

            Array(values).each { |value| store.add(:dns, { host: target, type: record_type, value: value }) }
          end
          spinner.success("DNS collection complete")
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
