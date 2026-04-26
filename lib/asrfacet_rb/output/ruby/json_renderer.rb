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
require_relative "../base_renderer"
require_relative "../runtime_detector"

module ASRFacet
  module Output
    module Ruby
      class JsonRenderer < BaseRenderer
        def render(output_path)
          write!(output_path, JSON.pretty_generate(payload))
          log_success("JSON", output_path)
        rescue StandardError => e
          raise ASRFacet::Error, "JSON render failed: #{e.message}"
        end

        private

        def payload
          {
            meta: {
              tool: "ASRFacet-Rb",
              version: version,
              target: @target,
              generated: iso_timestamp,
              engine: RuntimeDetector.engine_label
            },
            stats: @store.stats,
            subdomains: @store.subdomains,
            ips: @store.ips,
            ports: @store.ports,
            findings: sorted_findings,
            js_endpoints: @store.js_endpoints,
            errors: @store.errors,
            charts: @options[:charts] || {}
          }
        end
      end
    end
  end
end
