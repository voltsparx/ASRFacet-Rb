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

module ASRFacet::Output
  class JsonFormatter < BaseFormatter
    def format(results)
      payload = payload_for(results)
      JSON.pretty_generate(payload[:store].merge(
                             graph: payload[:graph].respond_to?(:to_h) ? payload[:graph].to_h : payload[:graph],
                             diff: payload[:diff],
                             top_assets: payload[:top_assets],
                             js_endpoints: payload[:js_endpoints],
                             correlations: payload[:correlations],
                             probabilistic_subdomains: payload[:probabilistic_subdomains],
                             generated_at: Time.now.iso8601
                           ).compact)
    rescue StandardError
      JSON.pretty_generate(generated_at: Time.now.iso8601)
    end
  end
end
