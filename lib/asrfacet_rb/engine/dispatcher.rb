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
  module Engine
    class Dispatcher
      def initialize(event_bus:, registry:, logger: nil)
        @bus = event_bus
        @registry = registry
        @logger = logger
      end

      def dispatch(event_type, asset, context = {})
        @logger&.info(event: :dispatch, type: event_type, asset: asset.to_s)
        @registry.for_event(event_type).each do |plugin|
          plugin.process(asset, context, @bus)
        rescue ASRFacet::PluginError => e
          @logger&.warn(event: :plugin_error, plugin: plugin.class.name, error: e.message)
        end
      end
    end
  end
end
