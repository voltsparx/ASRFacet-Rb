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
  module Core
    module Severity
      CRITICAL = :critical
      HIGH = :high
      MEDIUM = :medium
      LOW = :low
      INFO = :info

      COLORS = {
        critical: ASRFacet::Colors.severity_terminal(:critical),
        high: ASRFacet::Colors.severity_terminal(:high),
        medium: ASRFacet::Colors.severity_terminal(:medium),
        low: ASRFacet::Colors.severity_terminal(:low),
        info: ASRFacet::Colors.severity_terminal(:info)
      }.freeze

      ORDER = [CRITICAL, HIGH, MEDIUM, LOW, INFO].freeze
    end

    class Finding
      attr_reader :title, :severity, :description, :evidence, :host, :remediation, :timestamp

      def initialize(title:, severity:, description:, evidence: nil, host:, remediation:, timestamp: Time.now.iso8601)
        @title = title
        @severity = severity
        @description = description
        @evidence = evidence
        @host = host
        @remediation = remediation
        @timestamp = timestamp
      rescue StandardError
        @title = title.to_s
        @severity = severity
        @description = description.to_s
        @evidence = evidence
        @host = host.to_s
        @remediation = remediation.to_s
        @timestamp = Time.now.iso8601
      end

      def to_h
        {
          title: @title,
          severity: @severity,
          description: @description,
          evidence: @evidence,
          host: @host,
          remediation: @remediation,
          timestamp: @timestamp
        }
      rescue StandardError
        {}
      end

      def hash
        to_h.hash
      rescue StandardError
        super
      end

      def eql?(other)
        other.respond_to?(:to_h) && other.to_h == to_h
      rescue StandardError
        false
      end
    end

    module FindingBuilder
      def exposed_git(host)
        build_finding(
          title: "Exposed Git Repository",
          severity: Severity::HIGH,
          host: host,
          description: "The Git metadata endpoint appears to be publicly accessible.",
          remediation: "Block access to /.git paths and remove repository metadata from the web root.",
          evidence: "/.git/HEAD returned HTTP 200."
        )
      end

      def exposed_env(host)
        build_finding(
          title: "Exposed Environment File",
          severity: Severity::CRITICAL,
          host: host,
          description: "A .env file appears to be directly accessible over HTTP.",
          remediation: "Remove the file from the web root and rotate any credentials that may have been exposed.",
          evidence: "/.env returned HTTP 200."
        )
      end

      def subdomain_takeover(host, cname, service)
        build_finding(
          title: "Potential Subdomain Takeover",
          severity: Severity::HIGH,
          host: host,
          description: "The hostname points to #{cname}, which matches #{service} takeover indicators.",
          remediation: "Remove the dangling DNS record or reclaim the third-party service resource.",
          evidence: "CNAME matched a known takeover signature."
        )
      end

      def missing_security_header(host, header)
        build_finding(
          title: "Missing Security Header",
          severity: Severity::MEDIUM,
          host: host,
          description: "The HTTP response is missing the #{header} header.",
          remediation: "Set #{header} with a policy appropriate for the application.",
          evidence: "Header not present in baseline response."
        )
      end

      alias missing_header missing_security_header

      def cors_misconfiguration(host)
        build_finding(
          title: "Permissive CORS Configuration",
          severity: Severity::HIGH,
          host: host,
          description: "The application reflects an arbitrary Origin while allowing credentialed requests.",
          remediation: "Restrict allowed origins and disable credential sharing for untrusted domains.",
          evidence: "Origin https://evil.com was accepted with credentialed requests enabled."
        )
      end

      def expired_cert(host, date = nil)
        build_finding(
          title: "Expired TLS Certificate",
          severity: Severity::HIGH,
          host: host,
          description: "The TLS certificate presented by the host is expired.",
          remediation: "Renew and redeploy a valid TLS certificate chain.",
          evidence: date ? "Certificate expired on #{date}." : "Certificate not_after date is in the past."
        )
      end

      def directory_listing(host, path)
        build_finding(
          title: "Directory Listing Enabled",
          severity: Severity::LOW,
          host: host,
          description: "A directory index appears to be enabled at #{path}.",
          remediation: "Disable auto-indexing and restrict direct access to directory listings.",
          evidence: "Response body included 'Index of'."
        )
      end

      private

      def build_finding(title:, severity:, host:, description:, remediation:, evidence: nil)
        Finding.new(
          title: title,
          severity: severity,
          description: description,
          evidence: evidence,
          host: host,
          remediation: remediation
        ).to_h
      rescue StandardError
        Finding.new(
          title: title.to_s,
          severity: severity,
          description: description.to_s,
          host: host.to_s,
          remediation: remediation.to_s
        ).to_h
      end
    end
  end
end
