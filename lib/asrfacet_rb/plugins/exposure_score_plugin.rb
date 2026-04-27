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

module ASRFacet
  module Plugins
    class ExposureScorePlugin < Base
      priority 10
      plugin_family :session
      plugin_name "exposure_score"
      category "prioritization"
      description "Scores hosts by service exposure and generated findings."
      modes :scan, :portscan, :ports, :enum

      SERVICE_WEIGHTS = {
        22 => 3, 80 => 2, 443 => 2, 445 => 5, 3389 => 5,
        3306 => 5, 5432 => 4, 6379 => 5, 9200 => 5, 27017 => 5,
        5900 => 4, 2375 => 5, 6443 => 5
      }.freeze

      def apply(context)
        store = context[:store]
        return context if store.nil?

        by_host = Hash.new { |hash, key| hash[key] = { score: 0, ports: [], findings: 0 } }
        Array(store.all(:open_ports)).each do |entry|
          port = entry[:port].to_i
          host = entry[:host].to_s
          next if host.empty?

          by_host[host][:score] += SERVICE_WEIGHTS.fetch(port, 1)
          by_host[host][:ports] << port
        end

        Array(store.all(:findings)).each do |entry|
          host = entry[:host].to_s
          next if host.empty?

          by_host[host][:findings] += 1
          by_host[host][:score] += finding_weight(entry[:severity])
        end

        ranked = by_host.map do |host, data|
          {
            host: host,
            total_score: data[:score],
            exposed_ports: data[:ports].uniq.sort,
            findings: data[:findings],
            rationale: score_rationale(data)
          }
        end.sort_by { |entry| [-entry[:total_score], entry[:host]] }

        store.replace(:plugin_priority_targets, ranked)
        context
      rescue StandardError => e
        raise ASRFacet::PluginError, e.message
      end

      private

      def finding_weight(severity)
        case severity.to_s.downcase
        when "critical" then 6
        when "high" then 4
        when "medium" then 2
        else 1
        end
      rescue StandardError
        1
      end

      def score_rationale(data)
        parts = []
        parts << "#{data[:ports].uniq.count} exposed services" if data[:ports].any?
        parts << "#{data[:findings]} correlated findings" if data[:findings].positive?
        parts.empty? ? "low observed surface" : parts.join(" and ")
      rescue StandardError
        "scored from observed exposure"
      end
    end
  end
end
