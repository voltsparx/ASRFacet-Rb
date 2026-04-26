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

require_relative "base_source"

module ASRFacet
  module Intelligence
    module Sources
      class VirustotalSource < BaseSource
        def name = :virustotal

        def requires_key? = true

        def fetch(domain)
          return [] unless available?

          data = get_json(
            "https://www.virustotal.com/api/v3/domains/#{domain}/subdomains?limit=100",
            headers: { "x-apikey" => api_key.to_s }
          )
          return [] if data.nil?

          values = Array(data["data"]).map { |entry| entry["id"] }
          normalize_results(values, domain)
        rescue StandardError
          []
        end
      end
    end
  end
end
