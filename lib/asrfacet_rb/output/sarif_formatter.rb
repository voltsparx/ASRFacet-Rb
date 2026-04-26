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
  module Output
    class SarifFormatter < BaseFormatter
      def format(results)
        payload = payload_for(results)
        ASRFacet::Renderers::SarifRenderer.new(payload[:store], primary_target(payload[:store])).render
      rescue ASRFacet::Error
        ASRFacet::Renderers::SarifRenderer.new(ASRFacet::ResultStore.new, "target").render
      end
    end
  end
end
