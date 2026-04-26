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

require "uri"
require_relative "base_source"

module ASRFacet
  module Intelligence
    module Sources
      class CommoncrawlSource < BaseSource
        DEFAULT_INDEX = "https://index.commoncrawl.org/CC-MAIN-2024-10-index"

        def name = :commoncrawl

        def fetch(domain)
          body = get_text("#{DEFAULT_INDEX}?url=*.#{domain}&output=json&fl=url&limit=500")
          return [] if body.nil?

          values = body.lines.filter_map do |line|
            parsed = JSON.parse(line)
            URI.parse(parsed["url"].to_s).host
          rescue JSON::ParserError, URI::InvalidURIError
            nil
          end
          normalize_results(values, domain)
        rescue StandardError
          []
        end
      end
    end
  end
end
