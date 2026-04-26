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

begin
  require "caracal"
rescue LoadError
  Caracal = nil
end

require_relative "../base_renderer"

module ASRFacet
  module Output
    module Ruby
      class DocxRenderer < BaseRenderer
        SEVERITY_COLORS = {
          "critical" => "FF6767",
          "high" => "FF6767",
          "medium" => "F5B53D",
          "low" => "4FD18B",
          "informational" => "53C2F0"
        }.freeze

        def render(output_path)
          raise ASRFacet::Error, "Caracal is not installed" if Caracal.nil?

          payload = report_payload
          Caracal::Document.save(output_path) do |doc|
            build_cover(doc, payload)
            build_summary(doc, payload)
            build_chart_tables(doc, payload[:charts])
            build_table(doc, "Subdomains", %w[Host Sources], payload[:subdomains].map { |row| [row[:host], row[:sources].join(", ")] })
            build_table(doc, "IPs", %w[IP Class Ports], payload[:ips].map { |row| [row[:ip], row[:class], row[:ports].to_s] })
            build_table(doc, "Ports", %w[Host Port Service Banner], payload[:ports].map { |row| [row[:host], row[:port].to_s, row[:service], row[:banner]] })
            build_findings(doc, payload[:findings])
            build_table(doc, "JavaScript Endpoints", %w[Endpoint Method Source], payload[:js_endpoints].map { |row| [row[:endpoint], row[:method], row[:source]] })
            build_table(doc, "Errors", %w[Source Message Time], payload[:errors].map { |row| [row[:source], row[:message], row[:time]] })
          end
          log_success("DOCX", output_path)
        rescue ASRFacet::Error
          raise
        rescue Errno::EACCES, Errno::ENOENT, IOError, SystemCallError => e
          raise ASRFacet::Error, "DOCX render failed: #{e.message}"
        end

        private

        def build_cover(doc, payload)
          doc.h1 report_title
          doc.p "Target: #{payload[:meta][:target]}"
          doc.p "Generated: #{payload[:meta][:generated_at]}"
          doc.p "Engine: #{payload[:meta][:engine]}"
          doc.p "Version: #{payload[:meta][:version]}"
          doc.hr
        end

        def build_summary(doc, payload)
          doc.h2 "Summary"
          rows = [["Metric", "Value"]] + payload[:stats].map { |key, value| [key.to_s.tr("_", " "), value.to_s] }
          doc.table rows, border_size: 4
          doc.hr
        end

        def build_chart_tables(doc, charts)
          doc.h2 "Chart Data"
          build_table(doc, "Severity Distribution", %w[Label Value], Array(charts[:severity_distribution]).map { |row| [row[:label], row[:value].to_s] }, header: false)
          build_table(doc, "Port Frequency", %w[Port Count], Array(charts[:port_frequency]).map { |row| [row[:port].to_s, row[:value].to_s] }, header: false)
          build_table(doc, "Service Breakdown", %w[Service Count], Array(charts[:service_breakdown]).map { |row| [row[:label], row[:value].to_s] }, header: false)
          build_table(doc, "IP Class Distribution", %w[Class Count], Array(charts[:ip_class_distribution]).map { |row| [row[:label], row[:value].to_s] }, header: false)
          build_table(doc, "Subdomain Source Share", %w[Source Count], Array(charts[:subdomain_source_share]).map { |row| [row[:label], row[:value].to_s] }, header: false)
          build_table(doc, "Finding Timeline", %w[Date Count], Array(charts[:finding_timeline]).map { |row| [row[:label], row[:value].to_s] }, header: false)
        end

        def build_findings(doc, rows)
          doc.h2 "Findings"
          if rows.empty?
            doc.p "(none)"
            return
          end

          rows.each do |row|
            severity = row[:severity].to_s.downcase
            doc.h3(row[:title].to_s.empty? ? "Untitled" : row[:title].to_s)
            doc.p "Asset: #{row[:asset] || row[:host]}"
            doc.p do
              text "Severity: ", bold: true
              text row[:severity].to_s, color: SEVERITY_COLORS.fetch(severity, "53C2F0")
            end
            doc.p "Description: #{row[:description].to_s.empty? ? 'n/a' : row[:description]}"
            doc.hr
          end
        end

        def build_table(doc, title, headers, rows, header: true)
          doc.h2 title
          content = header ? [headers] + rows : [headers] + rows
          doc.table content, border_size: 4
        end
      end
    end
  end
end
