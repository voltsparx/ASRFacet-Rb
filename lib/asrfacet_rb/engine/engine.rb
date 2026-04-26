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

require_relative "event_bus"
require_relative "plugin_registry"
require_relative "dispatcher"

module ASRFacet
  module Engine
    class Engine
      attr_reader :bus, :registry, :dispatcher

      def initialize(config: nil, logger: nil)
        @config = config
        @logger = logger
        @bus = EventBus.new
        @registry = PluginRegistry.new
        @dispatcher = Dispatcher.new(event_bus: @bus, registry: @registry, logger: @logger)
        load_builtin_plugins
        load_user_plugins
      end

      def start
        @logger&.info(event: :engine_start)
        @running = true
      end

      def stop
        @running = false
        @logger&.info(event: :engine_stop)
      end

      def running?
        @running == true
      end

      private

      def load_builtin_plugins
        builtin_dir = File.join(__dir__, "..", "plugins")
        @registry.load_dir(builtin_dir)
        ObjectSpace.each_object(Class).select do |klass|
          klass < ASRFacet::Plugins::Base
        end.each { |klass| @registry.register(klass) }
      rescue ASRFacet::PluginError => e
        @logger&.warn(event: :builtin_plugin_load_error, error: e.message)
      end

      def load_user_plugins
        user_dir = File.join(Dir.pwd, "plugins")
        @registry.load_dir(user_dir)
      rescue ASRFacet::PluginError => e
        @logger&.warn(event: :user_plugin_load_error, error: e.message)
      end
    end
  end
end
