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

require "concurrent"

module ASRFacet
  module Engine
    class PluginRegistry
      attr_reader :plugins

      def initialize
        @plugins = Concurrent::Array.new
      end

      def register(plugin_class)
        instance = plugin_class.new
        @plugins << instance
        @plugins.sort_by!(&:priority)
        instance
      rescue StandardError => e
        raise ASRFacet::PluginError, e.message
      end

      def for_event(event_type)
        @plugins.select { |plugin| plugin.handles?(event_type) }
      end

      def load_dir(dir)
        return nil unless Dir.exist?(dir)

        Dir.glob(File.join(dir, "**", "*.rb")).sort.each do |file|
          require file
        end
      rescue LoadError, ScriptError => e
        raise ASRFacet::PluginError, e.message
      end
    end
  end
end
