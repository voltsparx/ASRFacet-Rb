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
  module Output
    class ChartDataBuilder
      def initialize(result_store)
        @store = result_store
      end

      def build
        {
          severity_distribution: severity_distribution,
          subdomain_source_share: subdomain_source_share,
          port_frequency: port_frequency,
          service_breakdown: service_breakdown,
          finding_timeline: finding_timeline,
          ip_class_distribution: ip_class_distribution
        }
      end

      def severity_distribution
        counts = Hash.new(0)
        Array(@store.findings).each do |finding|
          severity = finding[:severity]&.to_s&.downcase&.capitalize
          severity = "Informational" if severity.empty?
          counts[severity] += 1
        end
        counts.map { |label, value| { label: label, value: value } }
      end

      def port_frequency
        frequency = Hash.new(0)
        @store.ports.each_value do |ports|
          Array(ports).each { |port| frequency[port[:port].to_s] += 1 }
        end
        frequency.sort_by { |_port, count| -count }.first(10).map do |port, count|
          { port: port, count: count }
        end
      end

      def service_breakdown
        counts = Hash.new(0)
        @store.ports.each_value do |ports|
          Array(ports).each do |port|
            service = port[:service].to_s.downcase
            service = "unknown" if service.empty?
            counts[service] += 1
          end
        end
        counts.sort_by { |_service, count| -count }.first(8).map do |service, count|
          { label: service, value: count }
        end
      end

      def subdomain_source_share
        counts = Hash.new(0)
        Array(@store.respond_to?(:subdomains_with_sources) ? @store.subdomains_with_sources : []).each do |entry|
          source = entry[:source].to_s.capitalize
          source = "Unknown" if source.empty?
          counts[source] += 1
        end
        return [{ label: "All Sources", value: @store.subdomains.size }] if counts.empty?

        counts.map { |label, value| { label: label, value: value } }
      end

      def finding_timeline
        grouped = Array(@store.findings).group_by do |finding|
          stamp = finding[:found_at]
          stamp.respond_to?(:strftime) ? stamp.strftime("%H:%M") : "N/A"
        end.transform_values(&:size)
        grouped.map { |time, count| { time: time || "N/A", count: count } }.sort_by { |entry| entry[:time] }
      end

      def ip_class_distribution
        counts = { "Private" => 0, "Class A" => 0, "Class B" => 0, "Class C" => 0, "Other" => 0 }
        Array(@store.ips).each { |ip| counts[classify_ip(ip)] += 1 }
        counts.reject { |_label, value| value.zero? }.map { |label, value| { label: label, value: value } }
      end

      private

      def classify_ip(ip)
        octets = ip.to_s.split(".").map(&:to_i)
        return "Other" unless octets.size == 4

        first = octets[0]
        return "Private" if first == 10
        return "Private" if first == 172 && octets[1].between?(16, 31)
        return "Private" if first == 192 && octets[1] == 168
        return "Class A" if first.between?(1, 126)
        return "Class B" if first.between?(128, 191)
        return "Class C" if first.between?(192, 223)

        "Other"
      rescue ASRFacet::Error
        "Other"
      end
    end
  end
end
