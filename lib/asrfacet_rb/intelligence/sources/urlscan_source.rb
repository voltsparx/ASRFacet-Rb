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
      class UrlscanSource < BaseSource
        def name = :urlscan

        def fetch(domain)
          data = get_json("https://urlscan.io/api/v1/search/?q=domain:#{domain}&size=100")
          return [] if data.nil?

          values = Array(data["results"]).map { |entry| entry.dig("page", "domain") }
          normalize_results(values, domain)
        rescue StandardError
          []
        end
      end
    end
  end
end
