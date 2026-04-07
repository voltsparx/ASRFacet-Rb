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
  module Notifiers
    class WebhookNotifier
      CRITICAL_FINDING_TYPES = [
        "Exposed .git directory",
        "Exposed .env file",
        "Subdomain Takeover Candidate",
        "CORS Misconfiguration",
        "Directory Listing Enabled"
      ].freeze

      def initialize(webhook_url, platform: :slack)
        @url = webhook_url.to_s
        @platform = platform.to_sym
        @client = ASRFacet::HTTP::RetryableClient.new
        @enabled = !@url.empty?
      rescue StandardError
        @url = ""
        @platform = :slack
        @client = ASRFacet::HTTP::RetryableClient.new
        @enabled = false
      end

      def notify_finding(finding)
        return nil unless @enabled

        normalized = symbolize_keys(finding)
        severity = normalized[:severity].to_s.downcase.to_sym
        return nil unless %i[critical high].include?(severity)

        payload = build_payload(normalized)
        @client.post(@url, body: payload.to_json, headers: { "Content-Type" => "application/json" })
      rescue StandardError
        nil
      end

      def notify_scan_complete(store)
        return nil unless @enabled

        summary = {
          target: Array(store.all(:subdomains)).first,
          subdomains_found: store.all(:subdomains).size,
          critical_findings: store.all(:findings).count { |entry| symbolize_keys(entry)[:severity].to_s.downcase.to_sym == :critical },
          high_findings: store.all(:findings).count { |entry| symbolize_keys(entry)[:severity].to_s.downcase.to_sym == :high }
        }
        @client.post(
          @url,
          body: build_summary_payload(summary).to_json,
          headers: { "Content-Type" => "application/json" }
        )
      rescue StandardError
        nil
      end

      def build_payload(finding)
        title = finding[:title].to_s
        host = finding[:host].to_s
        description = finding[:description].to_s
        case @platform
        when :discord
          { content: "ALERT: #{title}\nHost: `#{host}`\n#{description}" }
        else
          { text: "ALERT: #{title}\nHost: #{host}\n#{description}" }
        end
      rescue StandardError
        {}
      end

      def build_summary_payload(summary)
        message = "Scan complete — #{summary[:subdomains_found]} subdomains, #{summary[:critical_findings]} critical findings"
        @platform == :discord ? { content: message } : { text: message }
      rescue StandardError
        {}
      end

      private

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
