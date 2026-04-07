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

module ASRFacet::Passive
  class ThreatCrowd < BaseSource
    def name
      "threatcrowd"
    end

    def run(domain, _api_keys = {})
      body = fetch("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=#{domain}")
      return [] if body.to_s.strip.empty?

      Array(JSON.parse(body)["subdomains"]).map(&:to_s).map(&:downcase).select do |hostname|
        hostname == domain || hostname.end_with?(".#{domain}")
      end.uniq.sort
    rescue StandardError
      []
    end
  end
end
