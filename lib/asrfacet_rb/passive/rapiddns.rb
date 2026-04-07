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

require "nokogiri"

module ASRFacet::Passive
  class RapidDNS < BaseSource
    def name
      "rapiddns"
    end

    def run(domain, _api_keys = {})
      body = fetch("https://rapiddns.io/subdomain/#{domain}?full=1")
      return [] if body.to_s.strip.empty?

      doc = Nokogiri::HTML(body)
      pattern = /(?:\A|\s)([a-z0-9][a-z0-9\-_\.]*\.#{Regexp.escape(domain)})(?:\s|\z)/i

      doc.css("td").each_with_object(Set.new) do |cell, memo|
        text = cell.text.to_s.strip.downcase
        match = text.match(pattern)
        memo << match[1] if match
      end.to_a.sort
    rescue StandardError
      []
    end
  end
end
