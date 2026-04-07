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

require "ipaddr"

module ASRFacet
  module Core
    class ScopeEngine
      def initialize(allowed_domains: [], allowed_ips: [], excluded_domains: [], excluded_ips: [])
        @allowed_domains = Array(allowed_domains).map { |entry| entry.to_s.downcase }.reject(&:empty?)
        @allowed_ips = Array(allowed_ips).map(&:to_s).reject(&:empty?)
        @excluded_domains = Array(excluded_domains).map { |entry| entry.to_s.downcase }.reject(&:empty?)
        @excluded_ips = Array(excluded_ips).map(&:to_s).reject(&:empty?)
      rescue StandardError
        @allowed_domains = []
        @allowed_ips = []
        @excluded_domains = []
        @excluded_ips = []
      end

      def in_scope?(target)
        value = target.to_s.downcase
        return false if value.empty?

        ip_target?(value) ? ip_in_scope?(value) : domain_in_scope?(value)
      rescue StandardError
        false
      end

      def filter(targets_array)
        Array(targets_array).select { |target| in_scope?(target) }
      rescue StandardError
        []
      end

      def wildcard_match?(domain, pattern)
        host = domain.to_s.downcase
        rule = pattern.to_s.downcase
        return false if host.empty? || rule.empty?
        return host.end_with?(rule[1..]) if rule.start_with?("*.")

        host == rule
      rescue StandardError
        false
      end

      def scope_report
        "In scope: #{@allowed_domains.count} domains, #{@allowed_ips.count} IPs. Excluded: #{@excluded_domains.count} domains, #{@excluded_ips.count} IPs."
      rescue StandardError
        "In scope: 0 domains, 0 IPs. Excluded: 0 domains, 0 IPs."
      end

      private

      def ip_target?(target)
        IPAddr.new(target)
        true
      rescue StandardError
        false
      end

      def ip_in_scope?(ip)
        return false if ip_matches_any?(ip, @excluded_ips)
        return true if @allowed_ips.empty?

        ip_matches_any?(ip, @allowed_ips)
      rescue StandardError
        false
      end

      def domain_in_scope?(domain)
        return false if @excluded_domains.any? { |pattern| wildcard_match?(domain, pattern) }
        return true if @allowed_domains.empty?

        @allowed_domains.any? { |pattern| wildcard_match?(domain, pattern) }
      rescue StandardError
        false
      end

      def ip_matches_any?(ip, patterns)
        patterns.any? do |pattern|
          if pattern.include?("/")
            IPAddr.new(pattern).include?(IPAddr.new(ip))
          else
            ip == pattern
          end
        end
      rescue StandardError
        false
      end
    end
  end
end
