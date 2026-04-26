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

require "time"

module ASRFacet
  module Output
    class ChartDataBuilder
      SEVERITY_ORDER = %w[critical high medium low informational].freeze

      def initialize(result_store)
        @store = result_store
      end

      def build
        {
          severity_distribution: severity_distribution,
          port_frequency: port_frequency,
          service_breakdown: service_breakdown,
          ip_class_distribution: ip_class_distribution,
          subdomain_source_share: subdomain_source_share,
          finding_timeline: finding_timeline
        }
      end

      def severity_distribution
        counts = Hash.new(0)
        findings.each do |finding|
          severity = finding[:severity].to_s.downcase
          severity = "informational" if severity.empty?
          counts[severity] += 1
        end

        SEVERITY_ORDER.filter_map do |severity|
          value = counts[severity]
          next if value.to_i.zero?

          { label: severity.capitalize, value: value }
        end
      end

      def port_frequency
        counts = Hash.new(0)
        port_rows.each { |entry| counts[entry[:port].to_i] += 1 }
        counts.sort_by { |port, count| [-count, port] }.first(10).map do |port, count|
          { port: port, label: port.to_s, count: count, value: count }
        end
      end

      def service_breakdown
        counts = Hash.new(0)
        port_rows.each do |entry|
          service = entry[:service].to_s.strip.downcase
          service = "unknown" if service.empty?
          counts[service] += 1
        end
        counts.sort_by { |service, count| [-count, service] }.map do |service, count|
          { label: service, value: count }
        end
      end

      def ip_class_distribution
        counts = Hash.new(0)
        ips.each { |ip| counts[classify_ip(ip)] += 1 }
        counts.sort_by { |label, _count| label }.map do |label, count|
          { label: label, value: count }
        end
      end

      def subdomain_source_share
        counts = Hash.new(0)
        source_rows.each do |entry|
          source = entry[:source].to_s.strip.downcase
          source = "unknown" if source.empty?
          counts[source] += 1
        end

        counts.sort_by { |source, count| [-count, source] }.map do |source, count|
          { label: source, value: count }
        end
      end

      def finding_timeline
        counts = Hash.new(0)
        findings.each do |finding|
          bucket = bucket_timestamp(finding[:found_at] || finding[:time] || finding[:timestamp])
          counts[bucket] += 1
        end

        counts.sort_by { |bucket, _count| bucket }.map do |bucket, count|
          { label: bucket, time: bucket, count: count, value: count }
        end
      end

      private

      def findings
        fetch_array(:findings).map { |entry| symbolize_hash(entry) }
      end

      def ips
        fetch_array(:ips).map(&:to_s).reject(&:empty?)
      end

      def source_rows
        fetch_array(:subdomains_with_sources).map { |entry| symbolize_hash(entry) }
      end

      def port_rows
        ports = fetch_hash(:ports)
        ports.each_with_object([]) do |(host, entries), memo|
          Array(entries).each do |entry|
            normalized = symbolize_hash(entry)
            memo << {
              host: host.to_s,
              port: normalized[:port].to_i,
              service: normalized[:service].to_s
            }
          end
        end
      end

      def bucket_timestamp(value)
        return "unknown" if value.nil?

        case value
        when Time
          value.utc.strftime("%Y-%m-%d")
        else
          Time.parse(value.to_s).utc.strftime("%Y-%m-%d")
        end
      rescue ArgumentError, TypeError
        "unknown"
      end

      def classify_ip(ip)
        octets = ip.to_s.split(".").map(&:to_i)
        return "Other" unless octets.size == 4

        first = octets[0]
        return "Private" if first == 10
        return "Private" if first == 172 && octets[1].between?(16, 31)
        return "Private" if first == 192 && octets[1] == 168
        return "Loopback" if first == 127
        return "Link Local" if first == 169 && octets[1] == 254
        return "Class A" if first.between?(1, 126)
        return "Class B" if first.between?(128, 191)
        return "Class C" if first.between?(192, 223)

        "Other"
      rescue NoMethodError, TypeError
        "Other"
      end

      def fetch_array(name)
        if @store.respond_to?(name)
          Array(@store.public_send(name))
        elsif @store.respond_to?(:all)
          Array(@store.all(name))
        else
          []
        end
      rescue ASRFacet::Error, NoMethodError, TypeError
        []
      end

      def fetch_hash(name)
        value = if @store.respond_to?(name)
                  @store.public_send(name)
                elsif @store.respond_to?(:to_h)
                  @store.to_h[name]
                end
        value.is_a?(Hash) ? value : {}
      rescue ASRFacet::Error, NoMethodError, TypeError
        {}
      end

      def symbolize_hash(value)
        return {} unless value.is_a?(Hash)

        value.each_with_object({}) do |(key, nested), memo|
          memo[key.to_sym] = nested
        end
      rescue NoMethodError, TypeError
        {}
      end
    end
  end
end
