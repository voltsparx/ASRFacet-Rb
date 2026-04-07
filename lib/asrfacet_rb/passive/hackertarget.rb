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

module ASRFacet::Passive
  class HackerTarget < BaseSource
    def name
      "hackertarget"
    end

    def run(domain, _api_keys = {})
      body = fetch("https://api.hackertarget.com/hostsearch/?q=#{domain}")
      return [] if body.to_s.strip.empty?

      body.lines.each_with_object(Set.new) do |line, memo|
        next if line.to_s.downcase.include?("error")

        hostname = line.split(",").first.to_s.strip.downcase
        memo << hostname if hostname == domain || hostname.end_with?(".#{domain}")
      end.to_a.sort
    rescue StandardError
      []
    end
  end
end
