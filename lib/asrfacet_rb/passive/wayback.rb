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
require "uri"

module ASRFacet::Passive
  class Wayback < BaseSource
    def name
      "wayback"
    end

    def run(domain, _api_keys = {})
      url = "https://webcache.googleusercontent.com/search?output=json"
      cdx_url = "https://web.archive.org/cdx/search/cdx?url=*.#{domain}/*&output=json&fl=original&collapse=urlkey"
      body = fetch(cdx_url) || fetch(url)
      return [] if body.to_s.strip.empty?

      JSON.parse(body).each_with_object(Set.new) do |row, memo|
        next unless row.is_a?(Array)

        target = row.first.to_s
        host = URI.parse(target).host.to_s.downcase
        memo << host if host == domain || host.end_with?(".#{domain}")
      rescue StandardError
        nil
      end.to_a.sort
    rescue StandardError
      []
    end
  end
end
