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

module ASRFacet
  module Filters
    class InterestingAssetFilter < Base
      priority 30
      filter_name "interesting_asset"
      category "focus"
      description "Produces a focused view of admin, auth, remote, and non-prod assets."
      modes :scan, :passive, :dns, :enum, :intel

      KEYWORDS = %w[admin vpn remote auth sso corp internal dev stage staging test backup old api app portal].freeze

      def apply(context)
        store = context[:store]
        return context if store.nil?

        interesting = Array(store.all(:subdomains)).select do |host|
          KEYWORDS.any? { |keyword| host.to_s.downcase.include?(keyword) }
        end
        store.replace(:interesting_subdomains, interesting)
        context
      rescue StandardError => e
        raise ASRFacet::PluginError, e.message
      end
    end
  end
end
