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

require "concurrent/map"

module ASRFacet
  class RateLimiter
    DEFAULT_QPS = {
      crtsh: 5.0,
      hackertarget: 2.0,
      wayback: 1.0,
      rapiddns: 2.0,
      alienvault: 2.0,
      bufferover: 2.0,
      virustotal: 4.0,
      urlscan: 5.0,
      commoncrawl: 1.0,
      securitytrails: 2.0,
      shodan: 1.0,
      censys: 1.0
    }.freeze

    def initialize(overrides = {}, clock: nil, sleeper: nil)
      @qps = Concurrent::Map.new
      DEFAULT_QPS.each { |source, qps| @qps[source] = qps }
      overrides.each { |source, qps| set_qps(source, qps) }
      @last_call = Concurrent::Map.new
      @mutexes = Concurrent::Map.new
      @clock = clock || -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }
      @sleeper = sleeper || ->(duration) { sleep(duration) }
    end

    def throttle(source)
      source_key = normalize_source(source)

      mutex_for(source_key).synchronize do
        qps = fetch_qps(source_key)
        interval = 1.0 / qps
        now = monotonic_time
        last = @last_call[source_key]
        wait_time = (last.to_f + interval) - now
        if wait_time.positive?
          @sleeper.call(wait_time)
          now = monotonic_time
        end

        @last_call[source_key] = now
      end
    rescue ASRFacet::RateLimitError
      raise
    rescue ArgumentError, NoMethodError, TypeError => e
      raise ASRFacet::RateLimitError, e.message
    end

    def set_qps(source, qps)
      value = Float(qps)
      raise ASRFacet::RateLimitError, "QPS must be positive for #{source}" unless value.positive?

      @qps[normalize_source(source)] = value
    rescue ASRFacet::RateLimitError
      raise
    rescue ArgumentError, TypeError => e
      raise ASRFacet::RateLimitError, e.message
    end

    private

    def fetch_qps(source)
      @qps.fetch(source, 1.0)
    rescue NoMethodError, TypeError => e
      raise ASRFacet::RateLimitError, e.message
    end

    def normalize_source(source)
      source.to_s.strip.downcase.to_sym
    rescue NoMethodError => e
      raise ASRFacet::RateLimitError, e.message
    end

    def monotonic_time
      @clock.call
    rescue NoMethodError => e
      raise ASRFacet::RateLimitError, e.message
    end

    def mutex_for(source)
      @mutexes.compute_if_absent(source) { Mutex.new }
    rescue NoMethodError => e
      raise ASRFacet::RateLimitError, e.message
    end
  end
end
