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
require "tempfile"
require_relative "../base_renderer"
require_relative "../runtime_detector"

module ASRFacet
  module Output
    module Js
      class JsDocxBridge < BaseRenderer
        SCRIPT = File.join(RuntimeDetector.js_dir, "docx", "docx_gen.js").freeze

        def render(output_path)
          ensure_installed
          tmp = write_payload
          run_script(tmp.path, output_path)
          log_success("DOCX (docx.js)", output_path)
        rescue ASRFacet::Error
          raise
        rescue StandardError => e
          raise ASRFacet::Error, "docx.js bridge failed: #{e.message}"
        ensure
          tmp&.close
          tmp&.unlink
        end

        private

        def ensure_installed
          lock = File.join(RuntimeDetector.js_dir, "package-lock.json")
          raise ASRFacet::Error, "JS deps missing. Run: cd #{RuntimeDetector.js_dir} && npm install" unless File.exist?(lock)
        end

        def write_payload
          tmp = Tempfile.new(["asrfacet_docx_", ".json"])
          tmp.write(build_payload.to_json)
          tmp.flush
          tmp
        end

        def build_payload
          {
            meta: { tool: "ASRFacet-Rb", version: version, target: @target, generated: iso_timestamp },
            stats: @store.stats,
            subdomains: @store.subdomains,
            ips: @store.ips,
            ports: @store.ports,
            findings: sorted_findings,
            js_endpoints: @store.js_endpoints,
            charts: @options[:charts] || {}
          }
        end

        def run_script(payload_path, output_path)
          result = system("node", SCRIPT, payload_path, output_path)
          raise ASRFacet::Error, "node docx_gen.js exited non-zero" unless result
        end
      end
    end
  end
end
