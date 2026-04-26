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
  module Intelligence
    module Analysis
      class AttackSurface
        RISKY_PORTS = %w[21 22 23 25 3389 5900 8080 8443].freeze
        HIGH_SEVERITIES = %w[critical high].freeze

        def summarize(graph)
          {
            domains: assets_for(graph, :domain, :fqdn),
            ips: assets_for(graph, :ip_address),
            netblocks: assets_for(graph, :netblock),
            asns: assets_for(graph, :asn),
            certificates: assets_for(graph, :certificate),
            emails: assets_for(graph, :email),
            technologies: assets_for(graph, :technology),
            open_ports: open_ports(graph),
            third_parties: third_parties(graph),
            critical_assets: critical_assets(graph)
          }
        end

        private

        def assets_for(graph, *types)
          types.flat_map { |type| graph.find_by_type(type) }.map(&:to_h).sort_by { |asset| [asset[:type].to_s, asset[:value].to_s] }
        end

        def open_ports(graph)
          ports = graph.find_by_type(:port).map(&:to_h)
          services = graph.find_by_type(:service).filter_map do |asset|
            next unless asset.properties.to_h[:port]

            asset.to_h
          end
          (ports + services).uniq do |entry|
            [
              entry.dig(:properties, :host).to_s,
              (entry.dig(:properties, :port) || entry[:value]).to_s
            ]
          end
            .sort_by { |asset| [asset.dig(:properties, :host).to_s, asset[:value].to_s] }
        end

        def third_parties(graph)
          (graph.find_by_type(:asn) + graph.find_by_type(:netblock)).select do |asset|
            asset.properties.to_h[:third_party]
          end.map(&:to_h).sort_by { |asset| [asset[:type].to_s, asset[:value].to_s] }
        end

        def critical_assets(graph)
          graph.to_h[:nodes].select do |asset|
            properties = asset[:properties].to_h
            severity = properties[:severity].to_s.downcase
            critical_flag = properties[:critical] == true
            risky_port = RISKY_PORTS.include?(asset[:value].to_s) || RISKY_PORTS.include?(properties[:port].to_s)
            critical_flag || HIGH_SEVERITIES.include?(severity) || risky_port
          end.sort_by { |asset| [asset[:type].to_s, asset[:value].to_s] }
        end
      end
    end
  end
end
