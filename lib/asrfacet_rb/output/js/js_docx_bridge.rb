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
          raise ASRFacet::Error, "Node.js is not available on PATH" unless RuntimeDetector.node_available?
          raise ASRFacet::Error, "JavaScript output dependencies are not installed" unless RuntimeDetector.js_installed?

          payload_file = Tempfile.new(["asrfacet_docx_payload", ".json"])
          payload_file.write(JSON.pretty_generate(report_payload))
          payload_file.flush

          success = system("node", SCRIPT, payload_file.path, output_path)
          raise ASRFacet::Error, "node docx_gen.js exited non-zero" unless success

          log_success("DOCX (docx.js)", output_path)
        rescue ASRFacet::Error
          raise
        ensure
          payload_file&.close
          payload_file&.unlink
        end
      end
    end
  end
end
