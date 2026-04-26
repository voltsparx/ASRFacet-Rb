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
require "time"

module ASRFacet
  module Renderers
    class SarifRenderer
      SARIF_VERSION = "2.1.0"
      SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

      def initialize(result_store, target)
        @store = result_store
        @target = target
      end

      def render
        JSON.pretty_generate(build_sarif)
      end

      private

      def build_sarif
        {
          "$schema" => SCHEMA_URI,
          "version" => SARIF_VERSION,
          "runs" => [build_run]
        }
      end

      def build_run
        {
          "tool" => build_tool,
          "results" => build_results,
          "artifacts" => [
            { "location" => { "uri" => "https://#{@target}" } }
          ]
        }
      end

      def build_tool
        {
          "driver" => {
            "name" => "ASRFacet-Rb",
            "version" => ASRFacet::VERSION,
            "informationUri" => "https://github.com/voltsparx/ASRFacet-Rb",
            "rules" => sarif_rules
          }
        }
      end

      def sarif_rules
        [
          rule("ASRF001", "exposed-subdomain", "Subdomain discovered and reachable"),
          rule("ASRF002", "open-port", "Open TCP port identified on asset"),
          rule("ASRF003", "http-service", "HTTP service fingerprinted"),
          rule("ASRF004", "finding", "Security finding identified during recon")
        ]
      end

      def rule(id, name, description)
        {
          "id" => id,
          "name" => name,
          "shortDescription" => { "text" => description },
          "helpUri" => "https://github.com/voltsparx/ASRFacet-Rb"
        }
      end

      def build_results
        results = []
        Array(@store.subdomains).each do |subdomain|
          results << sarif_result("ASRF001", "open", "Subdomain: #{subdomain}", subdomain)
        end
        Array(@store.findings).each do |finding|
          results << sarif_result(
            "ASRF004",
            severity_level(finding),
            finding[:title] || finding.to_s,
            finding[:asset] || finding[:host] || @target
          )
        end
        results
      end

      def sarif_result(rule_id, level, message, location_uri)
        {
          "ruleId" => rule_id,
          "level" => level,
          "message" => { "text" => message },
          "locations" => [
            {
              "physicalLocation" => {
                "artifactLocation" => {
                  "uri" => "https://#{location_uri}"
                }
              }
            }
          ]
        }
      end

      def severity_level(finding)
        case finding[:severity]&.to_s&.downcase
        when "high" then "error"
        when "medium" then "warning"
        else "note"
        end
      end
    end
  end
end
