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

require "base64"
require_relative "base_source"

module ASRFacet
  module Intelligence
    module Sources
      class CensysSource < BaseSource
        def name = :censys

        def requires_key? = true

        def fetch(domain)
          return [] unless available?

          data = get_json(
            "https://search.censys.io/api/v2/certificates/search?q=#{URI.encode_www_form_component(domain)}",
            headers: { "Authorization" => "Basic #{auth_token}" }
          )
          return [] if data.nil?

          values = Array(data.dig("result", "hits")).flat_map do |entry|
            Array(entry["names"]) + [entry["name"]]
          end
          normalize_results(values, domain)
        rescue StandardError
          []
        end

        private

        def auth_token
          value = api_key.to_s
          return "" if value.empty?

          Base64.strict_encode64(value.include?(":") ? value : "#{value}:")
        end
      end
    end
  end
end
