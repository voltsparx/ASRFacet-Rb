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
          base = output_path.delete_suffix(".csv")
          write_subdomains("#{base}_subdomains.csv")
          write_ips("#{base}_ips.csv")
          write_ports("#{base}_ports.csv")
          write_findings("#{base}_findings.csv")
          write_js_endpoints("#{base}_js_endpoints.csv")
          log_success("CSV (5 files)", "#{base}_*.csv")
        rescue StandardError => e
          raise ASRFacet::Error, "CSV render failed: #{e.message}"
        end

        private

        def meta_rows
          [["# ASRFacet-Rb Recon Report"], ["# Target", @target], ["# Generated", timestamp], ["# Version", version], []]
        end

        def write_subdomains(path)
          CSV.open(path, "w") do |csv|
            meta_rows.each { |row| csv << row }
            csv << %w[index subdomain]
            @store.subdomains.each_with_index { |subdomain, index| csv << [index + 1, subdomain] }
          end
        end

        def write_ips(path)
          CSV.open(path, "w") do |csv|
            meta_rows.each { |row| csv << row }
            csv << %w[index ip]
            @store.ips.each_with_index { |ip, index| csv << [index + 1, ip] }
          end
        end

        def write_ports(path)
          CSV.open(path, "w") do |csv|
            meta_rows.each { |row| csv << row }
            csv << %w[ip port service banner]
            @store.ports.each do |ip, ports|
              Array(ports).each { |port| csv << [ip, port[:port], port[:service], port[:banner]] }
            end
          end
        end

        def write_findings(path)
          CSV.open(path, "w") do |csv|
            meta_rows.each { |row| csv << row }
            csv << %w[index title severity asset description]
            sorted_findings.each_with_index do |finding, index|
              csv << [index + 1, finding[:title], finding[:severity], finding[:asset] || finding[:host], finding[:description]]
            end
          end
        end

        def write_js_endpoints(path)
          CSV.open(path, "w") do |csv|
            meta_rows.each { |row| csv << row }
            csv << %w[index endpoint]
            @store.js_endpoints.each_with_index { |endpoint, index| csv << [index + 1, endpoint] }
          end
        end
      end
    end
  end
end
