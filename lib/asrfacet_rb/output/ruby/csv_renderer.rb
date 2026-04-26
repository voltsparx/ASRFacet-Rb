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

require "csv"
require_relative "../base_renderer"

module ASRFacet
  module Output
    module Ruby
      class CsvRenderer < BaseRenderer
        def render(output_path)
          base = output_path.sub(/\.csv\z/i, "")
          write_csv("#{base}_subdomains.csv", %w[host sources], subdomain_rows.map { |row| [row[:host], row[:sources].join("|")] })
          write_csv("#{base}_ips.csv", %w[ip class ports], ip_rows.map { |row| [row[:ip], row[:class], row[:ports]] })
          write_csv("#{base}_ports.csv", %w[host port service banner], port_rows.map { |row| [row[:host], row[:port], row[:service], row[:banner]] })
          write_csv("#{base}_findings.csv", %w[title severity asset description], sorted_findings.map { |row| [row[:title], row[:severity], row[:asset] || row[:host], row[:description]] })
          write_csv("#{base}_js_endpoints.csv", %w[endpoint method source], js_endpoint_rows.map { |row| [row[:endpoint], row[:method], row[:source]] })
          log_success("CSV", "#{base}_*.csv")
        rescue ASRFacet::Error
          raise
        rescue Errno::EACCES, Errno::ENOENT, IOError, SystemCallError => e
          raise ASRFacet::Error, "CSV render failed: #{e.message}"
        end

        private

        def write_csv(path, headers, rows)
          FileUtils.mkdir_p(File.dirname(path))
          CSV.open(path, "wb") do |csv|
            metadata_rows.each { |row| csv << row }
            csv << headers
            rows.each { |row| csv << row }
          end
        end

        def metadata_rows
          [
            ["# ASRFacet-Rb Recon Report"],
            ["# Target", target],
            ["# Generated", timestamp],
            ["# Version", version],
            ["# Engine", options[:engine_label].to_s],
            []
          ]
        end
      end
    end
  end
end
