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
    class EventBus
      def initialize
        @handlers = Concurrent::Map.new { |hash, key| hash[key] = [] }
        @mutex = Mutex.new
      end

      def on(event, priority: 50, &block)
        return nil unless block

        @mutex.synchronize do
          @handlers[event.to_sym] << { priority: priority, handler: block }
          @handlers[event.to_sym].sort_by! { |entry| entry[:priority] }
        end
      end

      def emit(event, payload = {})
        handlers = @mutex.synchronize { Array(@handlers[event.to_sym]).dup }
        handlers.each do |entry|
          entry[:handler].call(payload)
        rescue ASRFacet::Error => e
          warn "[EventBus] handler error for #{event}: #{e.message}"
        end
      end

      def handler_count(event)
        Array(@handlers[event.to_sym]).size
      end
    end
  end
end
