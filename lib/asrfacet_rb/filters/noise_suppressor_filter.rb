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
    class NoiseSuppressorFilter < Base
      priority 50
      filter_name "noise_suppressor"
      category "noise"
      description "Applies the framework noise heuristics to HTTP results and findings."
      modes :scan, :passive, :enum, :intel

      def apply(context)
        store = context[:store]
        return context if store.nil?

        noise_filter = ASRFacet::Core::NoiseFilter.new
        store.replace(:http_responses, noise_filter.filter_http_results(store.all(:http_responses)))
        store.replace(:findings, noise_filter.filter_findings(store.all(:findings)))
        context
      rescue StandardError => e
        raise ASRFacet::PluginError, e.message
      end
    end
  end
end
