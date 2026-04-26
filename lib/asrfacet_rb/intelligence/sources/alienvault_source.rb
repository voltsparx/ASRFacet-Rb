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
      class AlienvaultSource < BaseSource
        def name = :alienvault

        def fetch(domain)
          url = "https://otx.alienvault.com/api/v1/indicators/domain/#{domain}/passive_dns"
          data = get_json(url)
          return [] if data.nil?

          values = Array(data["passive_dns"]).map { |entry| entry["hostname"] }
          normalize_results(values, domain)
        rescue StandardError
          []
        end
      end
    end
  end
end
