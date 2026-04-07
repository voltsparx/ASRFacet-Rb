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
  module Core
    class AdaptiveRateController
      def initialize(base_delay: 0, min_delay: 0, max_delay: 5000, thread_pool: nil)
        @delay = normalize_delay(base_delay, 0)
        @min_delay = normalize_delay(min_delay, 0)
        @max_delay = normalize_delay(max_delay, 5000)
        @pool = thread_pool
        @mutex = Mutex.new
        @consecutive_429s = 0
        @consecutive_ok = 0
      rescue StandardError
        @delay = 0
        @min_delay = 0
        @max_delay = 5000
        @pool = thread_pool
        @mutex = Mutex.new
        @consecutive_429s = 0
        @consecutive_ok = 0
      end

      def observe(status_code)
        @mutex.synchronize do
          code = status_code.to_i
          case code
          when 429
            @consecutive_429s += 1
            @consecutive_ok = 0
            back_off(multiplier: 2.0)
            shrink_pool!
            ASRFacet::Core::ThreadSafe.print_warning("Rate limit detected — slowing down (delay: #{@delay}ms)")
          when 200, 301, 302
            @consecutive_ok += 1
            @consecutive_429s = 0
            speed_up if @consecutive_ok > 20
          when 503
            @consecutive_429s = 0
            @consecutive_ok = 0
            back_off(multiplier: 1.5)
          else
            @consecutive_429s = 0
            @consecutive_ok = 0
          end
        end
        true
      rescue StandardError
        nil
      end

      def wait
        delay = current_delay
        sleep(delay / 1000.0) if delay.positive?
        true
      rescue StandardError
        nil
      end

      def back_off(multiplier: 2.0)
        @mutex.synchronize do
          @delay = [(@delay * multiplier).ceil, @max_delay].min
        end
        @delay
      rescue StandardError
        @max_delay
      end

      def speed_up
        @mutex.synchronize do
          @delay = [(@delay * 0.9).ceil, @min_delay].max
          @consecutive_ok = 0
        end
        @delay
      rescue StandardError
        @min_delay
      end

      def current_delay
        @mutex.synchronize { @delay }
      rescue StandardError
        0
      end

      private

      def shrink_pool!
        return unless @pool.respond_to?(:current_size) && @pool.respond_to?(:resize)

        current = @pool.current_size.to_i
        target = [(current * 0.75).floor, 1].max
        @pool.resize(target)
      rescue StandardError
        nil
      end

      def normalize_delay(value, default)
        parsed = value.to_i
        parsed.negative? ? default : parsed
      rescue StandardError
        default
      end
    end
  end
end
