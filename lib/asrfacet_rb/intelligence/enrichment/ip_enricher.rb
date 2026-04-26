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
require "resolv"

module ASRFacet
  module Intelligence
    module Enrichment
      class IpEnricher
        def initialize(http_client: ASRFacet::HTTP::RetryableClient.new, logger: nil, ptr_lookup: nil)
          @http_client = http_client
          @logger = logger
          @ptr_lookup = ptr_lookup || ->(ip) { Resolv.getname(ip.to_s) }
        end

        def enrich(ip, graph:)
          target = ip.to_s
          ptr = safe_ptr(target)
          geo = geolocation(target)

          properties = geo.merge(ptr: ptr).delete_if { |_key, value| value.to_s.empty? }
          ip_asset = graph.add_asset(
            ASRFacet::Intelligence::OAM.make(type: :ip_address, value: target, source: "ip_enricher", properties: properties)
          )

          unless ptr.to_s.empty?
            fqdn_asset = graph.add_asset(
              ASRFacet::Intelligence::OAM.make(type: :fqdn, value: ptr, source: "ip_enricher", properties: {})
            )
            graph.add_relation(from: ip_asset, to: fqdn_asset, type: :ptr_record, source: "ip_enricher")
          end

          if properties[:location]
            location_asset = graph.add_asset(
              ASRFacet::Intelligence::OAM.make(type: :location, value: properties[:location], source: "ip_enricher", properties: geo)
            )
            graph.add_relation(from: location_asset, to: ip_asset, type: :contains, source: "ip_enricher")
          end

          properties
        rescue StandardError => e
          log_warning("IP enrichment failed for #{ip}: #{e.message}")
          {}
        end

        private

        def safe_ptr(ip)
          @ptr_lookup.call(ip).to_s.downcase
        rescue StandardError
          ""
        end

        def geolocation(ip)
          response = @http_client.get("http://ip-api.com/json/#{ip}?fields=status,country,regionName,city,lat,lon,isp,org,as")
          return {} if response.nil?

          payload = JSON.parse(response.body.to_s)
          return {} if payload["status"].to_s == "fail"

          location = [payload["city"], payload["regionName"], payload["country"]].map(&:to_s).reject(&:empty?).join(", ")
          {
            country: payload["country"].to_s,
            region: payload["regionName"].to_s,
            city: payload["city"].to_s,
            latitude: payload["lat"],
            longitude: payload["lon"],
            isp: payload["isp"].to_s,
            organization: payload["org"].to_s,
            asn: payload["as"].to_s,
            location: location
          }.delete_if { |_key, value| value.to_s.empty? }
        rescue JSON::ParserError
          {}
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
