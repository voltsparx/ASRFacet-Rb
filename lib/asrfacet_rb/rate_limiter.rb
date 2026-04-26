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
  class RateLimiter
    DEFAULTS = {
      crtsh: 5.0,
      hackertarget: 2.0,
      wayback: 1.0,
      rapiddns: 2.0,
      alienvault: 2.0,
      shodan: 1.0,
      threatcrowd: 1.0,
      bufferover: 2.0,
      virustotal: 4.0,
      urlscan: 5.0,
      commoncrawl: 1.0,
      securitytrails: 2.0
    }.freeze

    def initialize(overrides = {})
      @limits = DEFAULTS.merge(overrides.transform_keys(&:to_sym))
      @last_call = Concurrent::Map.new
      @mutexes = Concurrent::Map.new { |hash, key| hash[key] = Mutex.new }
    end

    def throttle(source)
      source_key = source.to_sym
      qps = @limits.fetch(source_key, 2.0)
      interval = 1.0 / qps

      @mutexes[source_key].synchronize do
        last = @last_call[source_key]
        if last
          elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - last
          sleep(interval - elapsed) if elapsed < interval
        end
        @last_call[source_key] = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end
    end

    def set_qps(source, qps)
      @limits[source.to_sym] = qps.to_f
    end
  end
end
