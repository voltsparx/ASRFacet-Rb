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
  module Sources
    class CommoncrawlSource < BaseSource
      CDX_API = "https://index.commoncrawl.org/CC-MAIN-2024-10-index"

      def name = :commoncrawl

      def fetch(domain)
        url = "#{CDX_API}?url=*.#{domain}&output=json&fl=url&limit=500"
        body = get_text(url)
        return [] if body.nil?

        body.lines.filter_map do |line|
          parsed = JSON.parse(line.strip)
          URI.parse(parsed["url"]).host
        rescue JSON::ParserError, URI::InvalidURIError
          nil
        end.select { |host| host&.end_with?(".#{domain}") }
          .map(&:downcase)
          .uniq
      end
    end
  end
end
