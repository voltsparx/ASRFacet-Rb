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
      class BufferoverSource < BaseSource
        def name = :bufferover

        def fetch(domain)
          data = get_json("https://dns.bufferover.run/dns?q=.#{domain}")
          return [] if data.nil?

          values = Array(data["FDNS_A"]) + Array(data["RDNS"])
          values = values.map { |entry| entry.to_s.split(",").last }
          normalize_results(values, domain)
        rescue StandardError
          []
        end
      end
    end
  end
end
