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

module ASRFacet
  module Output
    module Ruby
      class JsonRenderer < BaseRenderer
        def render(output_path)
          write!(output_path, JSON.pretty_generate(report_payload))
          log_success("JSON", output_path)
        rescue ASRFacet::Error
          raise
        rescue JSON::GeneratorError, Errno::EACCES, Errno::ENOENT, IOError, SystemCallError => e
          raise ASRFacet::Error, "JSON render failed: #{e.message}"
        end
      end
    end
  end
end
