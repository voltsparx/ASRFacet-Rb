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
      class WaybackSource < BaseSource
        def name = :wayback

        def fetch(domain)
          url = "https://web.archive.org/cdx/search/cdx?url=*.#{domain}/*&output=text&fl=original&collapse=urlkey"
          body = get_text(url)
          return [] if body.nil?

          values = body.lines.filter_map do |line|
            URI.parse(line.strip).host
          rescue URI::InvalidURIError
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
