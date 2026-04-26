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

require "json"

module ASRFacet
  module Intelligence
    module Enrichment
      class AsnEnricher
        def initialize(http_client: ASRFacet::HTTP::RetryableClient.new, logger: nil, team_cymru_lookup: nil)
          @http_client = http_client
          @logger = logger
          @team_cymru_lookup = team_cymru_lookup
        end

        def enrich(ip, graph:)
          data = lookup(ip.to_s)
          return {} if data.empty?

          ip_asset = graph.add_asset(
            ASRFacet::Intelligence::OAM.make(type: :ip_address, value: ip, source: "asn_enricher", properties: data)
          )

          netblock_asset = nil
          if data[:netblock]
            netblock_asset = graph.add_asset(
              ASRFacet::Intelligence::OAM.make(
                type: :netblock,
                value: data[:netblock],
                source: "asn_enricher",
                properties: { cidr: data[:netblock], country: data[:country], owner: data[:description] }
              )
            )
            graph.add_relation(from: netblock_asset, to: ip_asset, type: :contains, source: "asn_enricher")
          end

          if data[:asn]
            asn_asset = graph.add_asset(
              ASRFacet::Intelligence::OAM.make(
                type: :asn,
                value: data[:asn],
                source: "asn_enricher",
                properties: { description: data[:description], country: data[:country] }
              )
            )
            graph.add_relation(from: netblock_asset || ip_asset, to: asn_asset, type: :managed_by, source: "asn_enricher")
          end

          data
        rescue StandardError => e
          log_warning("ASN enrichment failed for #{ip}: #{e.message}")
          {}
        end

        private

        def lookup(ip)
          lookup_bgp_tools(ip) || lookup_team_cymru(ip) || {}
        end

        def lookup_bgp_tools(ip)
          response = @http_client.get("https://bgp.tools/prefix/#{ip}.json")
          return nil if response.nil?

          payload = JSON.parse(response.body.to_s)
          normalize_asn_payload(payload)
        rescue JSON::ParserError
          nil
        end

        def lookup_team_cymru(ip)
          return nil if @team_cymru_lookup.nil?

          normalize_asn_payload(@team_cymru_lookup.call(ip))
        rescue StandardError
          nil
        end

        def normalize_asn_payload(payload)
          data = symbolize_keys(payload || {})
          result = data[:result].is_a?(Hash) ? data[:result] : data
          first = Array(result[:hits]).first.to_h
          source = result.empty? ? first : result

          asn = source[:asn] || source.dig(:autonomous_system, :asn) || source[:as_number]
          description = source[:description] || source[:name] || source.dig(:autonomous_system, :name)
          netblock = source[:prefix] || source[:netblock] || source.dig(:prefix, :cidr)
          country = source[:country] || source.dig(:country, :code) || source[:cc]

          return {} if [asn, netblock, description, country].all? { |value| value.to_s.empty? }

          {
            asn: asn.to_s.start_with?("AS") ? asn.to_s : "AS#{asn}",
            description: description.to_s,
            netblock: netblock.to_s,
            country: country.to_s
          }.delete_if { |_key, value| value.to_s.empty? }
        rescue StandardError
          {}
        end

        def symbolize_keys(value)
          case value
          when Hash
            value.each_with_object({}) do |(key, nested), memo|
              memo[key.to_sym] = symbolize_keys(nested)
            end
          when Array
            value.map { |entry| symbolize_keys(entry) }
          else
            value
          end
        end

        def log_warning(message)
          if @logger&.respond_to?(:warn)
            @logger.warn(message)
          elsif @logger&.respond_to?(:print_warning)
            @logger.print_warning(message)
          end
        rescue StandardError
          nil
        end
      end
    end
  end
end
