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
      class GithubSource < BaseSource
        def name = :github

        def fetch(domain)
          body = get_text("https://github.com/search?q=%22.#{domain}%22&type=code")
          extract_subdomains(body, domain)
        rescue StandardError
          []
        end
      end
    end
  end
end
