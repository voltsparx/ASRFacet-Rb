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

require "nokogiri"
require "set"
require "uri"

module ASRFacet
  module Engines
    class JsEndpointEngine
      ENDPOINT_PATTERNS = [
        /(?:fetch|axios\.(?:get|post|put|patch|delete|request)|open)\s*\(\s*['"]([^'"]+)['"]/i,
        /url\s*:\s*['"]([^'"]+)['"]/i,
        /['"]((?:\/|https?:\/\/|wss?:\/\/)[^"'\\\s]+)['"]/i,
        /['"](\.\.?\/[^"'\\\s]+)['"]/i
      ].freeze

      SECRET_PATTERNS = [
        /api[_-]?key\s*[:=]\s*['"][^'"]{8,}['"]/i,
        /token\s*[:=]\s*['"][^'"]{12,}['"]/i,
        /secret\s*[:=]\s*['"][^'"]{8,}['"]/i,
        /authorization\s*[:=]\s*['"]bearer\s+[^'"]+['"]/i,
        /-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----/i
      ].freeze

      def initialize(client: ASRFacet::HTTP::RetryableClient.new)
        @client = client
      end

      def run(base_url, js_urls)
        endpoints = Set.new
        findings = []
        scanned_files = Array(js_urls).map(&:to_s).reject(&:empty?).uniq

        scanned_files.each do |js_url|
          response = @client.get(js_url)
          next if response.nil?

          content = response.body.to_s
          extract_endpoints(content, base_url, js_url).each { |endpoint| endpoints << endpoint }
          findings << secret_finding(base_url, js_url) if potential_secret?(content)
        rescue StandardError
          nil
        end

        {
          js_files_scanned: scanned_files.count,
          endpoints_found: endpoints.to_a.reject(&:empty?).sort,
          potential_secrets: findings.count,
          findings: findings.uniq { |finding| [finding[:host], finding[:title], finding[:description]] }
        }
      rescue StandardError
        { js_files_scanned: 0, endpoints_found: [], potential_secrets: 0, findings: [] }
      end

      def extract_js_urls(html_body, base_url)
        doc = Nokogiri::HTML(html_body.to_s)
        doc.css("script[src]").filter_map do |script|
          src = script["src"].to_s.strip
          next if src.empty?
          next unless src.match?(/\.js(?:$|\?)/i)

          URI.join(base_url.to_s, src).to_s
        rescue StandardError
          nil
        end.uniq.sort
      rescue StandardError
        []
      end

      private

      def extract_endpoints(content, base_url, js_url)
        matches = Set.new
        ENDPOINT_PATTERNS.each do |pattern|
          content.to_enum(:scan, pattern).each do
            raw = Regexp.last_match(1).to_s
            normalized = normalize_endpoint(raw, base_url, js_url)
            matches << normalized unless normalized.empty?
          rescue StandardError
            nil
          end
        end
        matches.to_a
      rescue StandardError
        []
      end

      def normalize_endpoint(match, base_url, js_url)
        candidate = match.to_s.strip.gsub(/\A['"]|['"]\z/, "")
        return "" if candidate.empty?
        return "" if candidate.start_with?("data:", "javascript:", "#")
        return "" unless candidate.match?(%r{\A(?:/|https?://|wss?://|\.\.?/)})

        URI.join(js_url.to_s, candidate).to_s
      rescue StandardError
        URI.join(base_url.to_s, candidate.to_s).to_s
      rescue StandardError
        ""
      end

      def potential_secret?(content)
        SECRET_PATTERNS.any? { |pattern| content.to_s.match?(pattern) }
      rescue StandardError
        false
      end

      def secret_finding(base_url, js_url)
        host = URI.parse(base_url.to_s).host.to_s
        {
          title: "Potential Secret Pattern in JavaScript",
          severity: ASRFacet::Core::Severity::MEDIUM,
          host: host,
          status: "potential secret found",
          description: "A JavaScript file exposed a pattern consistent with a credential or key, but the value was intentionally not recorded.",
          remediation: "Review #{js_url} and move secrets to server-side storage or rotate them if real values were exposed."
        }
      rescue StandardError
        {
          title: "Potential Secret Pattern in JavaScript",
          severity: ASRFacet::Core::Severity::MEDIUM,
          host: base_url.to_s,
          status: "potential secret found",
          description: "A JavaScript file exposed a potential secret pattern, but the value was intentionally not recorded.",
          remediation: "Review the affected JavaScript asset and rotate any exposed credentials."
        }
      end
    end
  end
end
