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
      class CrtshSource < BaseSource
        def name = :crtsh

        def fetch(domain)
          data = get_json("https://crt.sh/?q=%25.#{domain}&output=json")
          return [] if data.nil?

          values = Array(data).flat_map do |entry|
            [entry["common_name"], entry["name_value"]].compact.flat_map { |item| item.to_s.split(/\s+/) }
          end
          normalize_results(values, domain)
        rescue StandardError
          []
        end
      end
    end
  end
end
