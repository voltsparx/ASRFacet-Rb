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
require "openssl"
require "set"

module ASRFacet
  module Intelligence
    module Enrichment
      class CertificateEnricher
        include ASRFacet::Mixins::Network

        DEFAULT_PORTS = [443, 8443].freeze

        def initialize(event_bus: nil, logger: nil, http_client: ASRFacet::HTTP::RetryableClient.new, cert_fetcher: nil, ports: DEFAULT_PORTS)
          @event_bus = event_bus
          @logger = logger
          @http_client = http_client
          @cert_fetcher = cert_fetcher || method(:ssl_cert)
          @ports = Array(ports)
        end

        def enrich(host, graph:)
          target = host.to_s.downcase
          host_asset = graph.add_asset(
            ASRFacet::Intelligence::OAM.make(type: :fqdn, value: target, source: "certificate_enricher", properties: {})
          )

          certificates = []
          seen_sans = Set.new

          @ports.each do |port|
            cert = @cert_fetcher.call(target, port: port)
            next if cert.nil?

            normalized = normalize_certificate(cert, target, port)
            certificates << normalized

            cert_asset = graph.add_asset(
              ASRFacet::Intelligence::OAM.make(
                type: :certificate,
                value: normalized[:serial],
                source: "certificate_enricher",
                properties: normalized
              )
            )
            graph.add_relation(from: host_asset, to: cert_asset, type: :has_certificate, source: "certificate_enricher", properties: { port: port })

            Array(normalized[:sans]).each do |san|
              fqdn_asset = graph.add_asset(
                ASRFacet::Intelligence::OAM.make(type: :fqdn, value: san, source: "certificate_enricher", properties: {})
              )
              graph.add_relation(from: cert_asset, to: fqdn_asset, type: :san_entry, source: "certificate_enricher")
              next if seen_sans.include?(san)

              seen_sans << san
              emit_subdomain(target, san)
            end
          end

          historical = historical_sans(target)
          historical.each do |san|
            next if seen_sans.include?(san)

            seen_sans << san
            emit_subdomain(target, san)
          end

          {
            host: target,
            certificates: certificates,
            historical_sans: historical
          }
        rescue StandardError => e
          log_warning("Certificate enrichment failed for #{host}: #{e.message}")
          {}
        end

        private

        def normalize_certificate(cert, host, port)
          {
            host: host,
            port: port,
            common_name: common_name(cert),
            sans: subject_alt_names(cert),
            issuer: cert.issuer.to_s,
            valid_from: cert.not_before.to_s,
            valid_to: cert.not_after.to_s,
            serial: serial_hex(cert)
          }
        end

        def historical_sans(host)
          response = @http_client.get("https://crt.sh/?q=%25.#{host}&output=json")
          return [] if response.nil?

          payload = JSON.parse(response.body.to_s)
          values = Array(payload).flat_map do |entry|
            [entry["common_name"], entry["name_value"]].compact.flat_map { |value| value.to_s.split(/\s+/) }
          end
          values.map(&:downcase).select { |entry| entry == host || entry.end_with?(".#{host.split('.', 2).last}") }.uniq.sort
        rescue JSON::ParserError
          []
        end

        def common_name(cert)
          Array(cert.subject.to_a).find { |entry| entry[0] == "CN" }.to_a[1].to_s
        rescue StandardError
          ""
        end

        def subject_alt_names(cert)
          extension = Array(cert.extensions).find { |entry| entry.oid == "subjectAltName" }
          return [] if extension.nil?

          extension.value.to_s.split(",").map do |entry|
            entry.to_s.strip.sub(/\ADNS:/, "").sub(/\A\*\./, "").downcase
          end.reject(&:empty?).uniq.sort
        rescue StandardError
          []
        end

        def serial_hex(cert)
          value = cert.serial
          value.respond_to?(:to_i) ? value.to_i.to_s(16) : value.to_s
        rescue StandardError
          cert.to_s
        end

        def emit_subdomain(parent, san)
          return if @event_bus.nil?

          @event_bus.emit(
            :subdomain,
            {
              host: san,
              parent: parent,
              data: { source: "certificate_enricher" }
            },
            dispatch_now: true
          )
        rescue StandardError
          nil
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
