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
  module Core
    class NoiseFilter
      NOISE_SIGNATURES = [
        /parking/i,
        /under construction/i,
        /coming soon/i,
        /default nginx/i,
        /default apache/i,
        /it works/i,
        /403 forbidden/i,
        /cloudflare.*error/i
      ].freeze

      LOW_VALUE_STATUS = [301, 302, 403].freeze

      def filter_http_results(results)
        Array(results).map { |entry| symbolize_keys(entry) }.reject do |result|
          body = result[:body_preview].to_s
          status = (result[:status] || result[:status_code]).to_i
          noisy_body?(body) || low_value_response?(result, status)
        end
      rescue StandardError
        []
      end

      def filter_findings(findings)
        seen = {}
        filtered = Array(findings).map { |finding| symbolize_keys(finding) }.reject do |finding|
          key = [finding[:host].to_s, finding[:title].to_s]
          duplicate = seen[key]
          seen[key] = true
          duplicate
        end
        filtered.sort_by { |finding| ASRFacet::Core::Severity::ORDER.index(finding[:severity].to_sym) || 999 }
      rescue StandardError
        []
      end

      def filter_subdomains(subdomains, resolved_ips)
        ip_map = normalize_ip_map(resolved_ips)
        Array(subdomains).select do |subdomain|
          Array(ip_map[subdomain.to_s.downcase]).any?
        end
      rescue StandardError
        []
      end

      private

      def noisy_body?(body)
        NOISE_SIGNATURES.any? { |signature| body.match?(signature) }
      rescue StandardError
        false
      end

      def low_value_response?(result, status)
        return false unless LOW_VALUE_STATUS.include?(status)

        Array(result[:interesting_paths]).empty? && Array(result[:technologies]).empty?
      rescue StandardError
        false
      end

      def normalize_ip_map(resolved_ips)
        case resolved_ips
        when Hash
          resolved_ips.each_with_object({}) do |(key, value), memo|
            memo[key.to_s.downcase] = Array(value).map(&:to_s).reject(&:empty?)
          end
        when Array
          resolved_ips.each_with_object({}) do |entry, memo|
            data = symbolize_keys(entry)
            host = data[:host] || data[:subdomain]
            next if host.to_s.empty?

            ips = Array(data[:ips])
            ips << data[:value] if %i[a aaaa].include?(data[:type].to_sym)
            memo[host.to_s.downcase] ||= []
            memo[host.to_s.downcase].concat(ips.map(&:to_s))
            memo[host.to_s.downcase].uniq!
          end
        else
          {}
        end
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
      rescue StandardError
        {}
      end
    end
  end
end
