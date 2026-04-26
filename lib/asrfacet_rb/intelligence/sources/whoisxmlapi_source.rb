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
      class WhoisxmlapiSource < BaseSource
        def name = :whoisxmlapi

        def requires_key? = true

        def fetch(domain)
          return [] unless available?

          data = get_json("https://subdomains.whoisxmlapi.com/api/v1?apiKey=#{api_key}&domainName=#{domain}")
          return [] if data.nil?

          values = Array(data["result"]).flat_map do |entry|
            entry.is_a?(Hash) ? Array(entry["name"]) + Array(entry["domain"]) : entry
          end
          normalize_results(values, domain)
        rescue StandardError
          []
        end
      end
    end
  end
end
