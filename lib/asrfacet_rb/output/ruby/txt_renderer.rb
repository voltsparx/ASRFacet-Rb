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

require "erb"
require_relative "../base_renderer"

module ASRFacet
  module Output
    module Ruby
      class TxtRenderer < BaseRenderer
        WIDTH = 72
        FULL = ("=" * WIDTH).freeze
        DASH = ("-" * WIDTH).freeze
        BAR_WIDTH = 28

        def render(output_path)
          write!(output_path, build_report)
          log_success("TXT", output_path)
        rescue ASRFacet::Error
          raise
        rescue Errno::EACCES, Errno::ENOENT, IOError, SystemCallError => e
          raise ASRFacet::Error, "TXT render failed: #{e.message}"
        end

        private

        def build_report
          [
            FULL,
            center(report_title),
            center("Target: #{target}"),
            center("Generated: #{timestamp}"),
            center("Engine: #{options[:engine_label]}"),
            FULL,
            summary_section,
            chart_section("Severity Distribution", charts[:severity_distribution], :label),
            chart_section("Port Frequency", charts[:port_frequency], :port),
            subdomain_section,
            ip_section,
            port_section,
            finding_section,
            js_section,
            error_section,
            footer_section
          ].join("\n\n")
        end

        def summary_section
          rows = [
            ["Subdomains", stats[:subdomains]],
            ["IPs", stats[:ips]],
            ["Ports", stats[:ports]],
            ["Findings", stats[:findings]],
            ["JS Endpoints", stats[:js_endpoints]],
            ["Errors", stats[:errors]]
          ]
          section("Executive Summary", rows.map { |label, value| "#{label.ljust(16)} #{value}" })
        end

        def subdomain_section
          rows = subdomain_rows.map do |row|
            sources = row[:sources].empty? ? "unknown" : row[:sources].join(", ")
            wrap_row("Host: #{row[:host]} | Sources: #{sources}")
          end.flatten
          section("Subdomains", rows)
        end

        def ip_section
          rows = ip_rows.map do |row|
            wrap_row("IP: #{row[:ip]} | Class: #{row[:class]} | Ports: #{row[:ports]}")
          end.flatten
          section("IP Inventory", rows)
        end

        def port_section
          rows = port_rows.map do |row|
            details = "Host: #{row[:host]} | Port: #{row[:port]} | "
            details += "Service: #{blank_to_unknown(row[:service])} | "
            details += "Banner: #{blank_to_unknown(row[:banner])}"
            wrap_row(details)
          end.flatten
          section("Open Ports", rows)
        end

        def finding_section
          rows = sorted_findings.flat_map do |finding|
            [
              wrap_row("Title: #{finding[:title].to_s.empty? ? 'Untitled' : finding[:title]}"),
              wrap_row("Severity: #{finding[:severity].to_s.capitalize} | Asset: #{finding[:asset] || finding[:host]}"),
              wrap_row("Details: #{finding[:description].to_s.empty? ? 'n/a' : finding[:description]}")
            ].flatten + [DASH]
          end
          rows.pop if rows.last == DASH
          section("Findings", rows)
        end

        def js_section
          rows = js_endpoint_rows.map do |row|
            wrap_row("Endpoint: #{row[:endpoint]} | Method: #{row[:method]} | Source: #{blank_to_unknown(row[:source])}")
          end.flatten
          section("JavaScript Endpoints", rows)
        end

        def error_section
          rows = error_rows.map do |row|
            wrap_row("Source: #{blank_to_unknown(row[:source])} | Message: #{blank_to_unknown(row[:message])} | Time: #{blank_to_unknown(row[:time])}")
          end.flatten
          section("Errors", rows)
        end

        def footer_section
          [
            FULL,
            center("ASRFacet-Rb v#{version}"),
            center("Authorized lab and reporting use only."),
            FULL
          ].join("\n")
        end

        def chart_section(title, data, key)
          rows = Array(data).map do |entry|
            label = key == :port ? "Port #{entry[:port]}" : entry[:label].to_s
            ascii_bar(label, entry[:value] || entry[:count])
          end.flatten
          section(title, rows)
        end

        def section(title, rows)
          content = Array(rows).compact.flatten
          content = ["(none)"] if content.empty?
          [
            title_bar(title),
            content.join("\n")
          ].join("\n")
        end

        def title_bar(title)
          centered = center(title.upcase)
          [DASH, centered, DASH].join("\n")
        end

        def ascii_bar(label, value)
          count = value.to_i
          width = [count, BAR_WIDTH].min
          ["#{label.to_s.ljust(24)} #{'#' * width} #{count}".slice(0, WIDTH)]
        end

        def wrap_row(text)
          line_width = WIDTH - 2
          words = text.to_s.split(/\s+/)
          return [""] if words.empty?

          lines = []
          current = +""
          words.each do |word|
            if current.empty?
              current << word
            elsif "#{current} #{word}".length <= line_width
              current << " #{word}"
            else
              lines << current
              current = +word
            end
          end
          lines << current unless current.empty?
          lines.map { |line| line[0, line_width] }
        end

        def center(text)
          text.to_s.center(WIDTH)
        end

        def blank_to_unknown(value)
          text = value.to_s.strip
          text.empty? ? "unknown" : text
        end
      end
    end
  end
end
