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

require "json"
require "time"

module ASRFacet
  class StructuredLogger
    LEVELS = %i[debug info warn error].freeze

    def initialize(stream_path: nil, level: :info)
      @level = level
      @stream_io = stream_path ? File.open(stream_path, "a") : nil
      @console_io = $stderr
    end

    LEVELS.each do |level_name|
      define_method(level_name) do |event_hash|
        log(level_name, event_hash)
      end
    end

    def close
      @stream_io&.close
    end

    private

    def log(level, event_hash)
      return if LEVELS.index(level) < LEVELS.index(@level)

      entry = {
        timestamp: Time.now.iso8601(3),
        level: level.to_s.upcase
      }.merge(event_hash)

      @stream_io&.puts(entry.to_json)
      @stream_io&.flush
      return unless %i[warn error].include?(level)

      color = level == :error ? "\e[31m" : "\e[33m"
      @console_io.puts("#{color}[#{level.upcase}]\e[0m #{event_hash[:event]}: #{event_hash[:error] || event_hash[:message]}")
    end
  end
end
