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

require "json"

module ASRFacet
  module Output
    class TxtFormatter < BaseFormatter
      def format(results)
        payload = payload_for(results)
        store = payload[:store]

        sections = []
        sections << render_block("Scan Overview", overview_lines(payload))
        sections << render_block("What It Means", summary_narrative(payload))
        sections << render_block("Recommended Next Steps", recommendations_for(payload))
        sections << render_block("Subdomains", Array(store[:subdomains]).sort)
        sections << render_block("Open Ports", Array(store[:open_ports]).map { |entry| "#{entry[:host]}:#{entry[:port]} #{entry[:service]} | banner=#{entry[:banner]}" })
        sections << render_block("HTTP Exposure", Array(store[:http_responses]).map { |entry| "#{entry[:host]} | status=#{entry[:status] || entry[:status_code]} | title=#{entry[:title]} | technologies=#{Array(entry[:technologies]).join(', ')}" })
        sections << render_block("Findings", Array(store[:findings]).map { |finding| "#{finding[:severity].to_s.upcase}: #{finding[:host]} - #{finding[:title]}\n  Why it matters: #{finding[:description]}\n  Recommendation: #{finding[:remediation]}" })
        sections << render_block("JavaScript Endpoints", Array(payload.dig(:js_endpoints, :endpoints_found)))
        sections << render_block("SPA Endpoints", Array(store[:spa_endpoints]).map { |entry| "#{entry[:method]} #{entry[:url]} (from #{entry[:discovered_from]})" })
        sections << render_block("DNS Records", Array(store[:dns]).map { |entry| "#{entry[:host]} #{entry[:type]} #{entry[:value]}" })
        sections << render_block("Correlations", Array(payload[:correlations]).map { |entry| JSON.generate(entry) })
        sections << render_block("Change Summary", [payload[:change_summary].to_s, JSON.pretty_generate(payload[:diff] || {})])
        sections << render_block("Stored Artifacts", artifact_rows(payload).map { |name, path| "#{name}: #{path}" })
        sections.compact.join("\n\n")
      rescue StandardError
        ""
      end

      private

      def overview_lines(payload)
        counts = counts_for(payload[:store])
        [
          "Target: #{primary_target(payload[:store])}",
          "Generated: #{payload.dig(:meta, :generated_at)}",
          "Output root: #{payload.dig(:meta, :output_directory)}",
          "Subdomains: #{counts[:subdomains]}",
          "Resolved IPs: #{counts[:ips]}",
          "Open ports: #{counts[:open_ports]}",
          "Web responses: #{counts[:http_responses]}",
          "Findings: #{counts[:findings]}",
          "JavaScript endpoints: #{counts[:js_endpoints]}",
          "SPA endpoints: #{counts[:spa_endpoints]}"
        ]
      rescue StandardError
        []
      end

      def render_block(title, lines)
        values = Array(lines).map(&:to_s).reject { |line| line.strip.empty? }
        return nil if values.empty?

        ([title, "-" * title.length] + values).join("\n")
      rescue StandardError
        nil
      end
    end
  end
end
