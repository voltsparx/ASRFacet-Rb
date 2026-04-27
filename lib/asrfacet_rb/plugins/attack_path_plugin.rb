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
    class AttackPathPlugin < Base
      priority 20
      plugin_family :session
      plugin_name "attack_path"
      category "analysis"
      description "Builds actionable path summaries from exposed hosts and services."
      modes :scan, :portscan, :ports, :enum

      def apply(context)
        store = context[:store]
        return context if store.nil?

        paths = Array(store.all(:open_ports)).filter_map do |entry|
          path_for(entry)
        end
        store.replace(:attack_paths, paths.uniq)
        context
      rescue StandardError => e
        raise ASRFacet::PluginError, e.message
      end

      private

      def path_for(entry)
        host = entry[:host].to_s
        port = entry[:port].to_i
        service = entry[:service].to_s
        return nil if host.empty? || port.zero?

        stage = case port
                when 22, 3389, 5900
                  "remote access surface"
                when 80, 443, 8080, 8443
                  "application entry point"
                when 3306, 5432, 6379, 9200, 27017
                  "data-plane exposure"
                when 445, 139
                  "lateral movement surface"
                else
                  "service pivot"
                end
        {
          host: host,
          port: port,
          service: service.empty? ? "unknown" : service,
          path: "#{host}:#{port} -> #{stage}",
          recommendation: recommendation_for(port)
        }
      rescue StandardError
        nil
      end

      def recommendation_for(port)
        case port.to_i
        when 22, 3389, 5900
          "Validate authentication posture, exposed remote access, and session entry points."
        when 80, 443, 8080, 8443
          "Review application routes, login panels, exposed APIs, and reachable administrative paths."
        when 3306, 5432, 6379, 9200, 27017
          "Prioritize direct data exposure, auth controls, and sensitive storage paths."
        when 445, 139
          "Review file-sharing exposure, trust boundaries, and internal pivot potential."
        else
          "Inspect banner, version data, and linked findings for the next pivot."
        end
      rescue StandardError
        "Inspect the linked exposure for the next pivot."
      end
    end
  end
end
