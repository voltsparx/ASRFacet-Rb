# frozen_string_literal: true
# For use only on systems you own or have explicit
# written authorization to test.
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
  module Scanner
    class Timing
      Template = Struct.new(
        :level,
        :name,
        :min_rtt_timeout,
        :max_rtt_timeout,
        :initial_rtt_timeout,
        :max_retries,
        :host_timeout,
        :scan_delay,
        :max_scan_delay,
        :min_parallelism,
        :max_parallelism,
        :min_hostgroup,
        :max_hostgroup,
        keyword_init: true
      ) do
        def to_h
          {
            level: level,
            name: name,
            min_rtt_timeout: min_rtt_timeout,
            max_rtt_timeout: max_rtt_timeout,
            initial_rtt_timeout: initial_rtt_timeout,
            max_retries: max_retries,
            host_timeout: host_timeout,
            scan_delay: scan_delay,
            max_scan_delay: max_scan_delay,
            min_parallelism: min_parallelism,
            max_parallelism: max_parallelism,
            min_hostgroup: min_hostgroup,
            max_hostgroup: max_hostgroup
          }
        end
      end

      DEFAULTS = {
        min_rtt_timeout: 100,
        max_rtt_timeout: 10_000,
        initial_rtt_timeout: 1_000,
        max_retries: 10,
        host_timeout: 0,
        scan_delay: 0,
        max_scan_delay: 1_000,
        min_parallelism: 0,
        max_parallelism: 0,
        min_hostgroup: 1,
        max_hostgroup: 100_000
      }.freeze

      TEMPLATES = {
        0 => Template.new(level: 0, name: "paranoid", **DEFAULTS.merge(max_rtt_timeout: 300_000, initial_rtt_timeout: 300_000, scan_delay: 300_000, min_parallelism: 1, max_parallelism: 1)),
        1 => Template.new(level: 1, name: "sneaky", **DEFAULTS.merge(max_rtt_timeout: 15_000, initial_rtt_timeout: 15_000, scan_delay: 15_000, min_parallelism: 1, max_parallelism: 1)),
        2 => Template.new(level: 2, name: "polite", **DEFAULTS.merge(scan_delay: 400, min_parallelism: 1, max_parallelism: 1)),
        3 => Template.new(level: 3, name: "normal", **DEFAULTS),
        4 => Template.new(level: 4, name: "aggressive", **DEFAULTS.merge(min_rtt_timeout: 100, max_rtt_timeout: 1_250, initial_rtt_timeout: 500, max_retries: 6, max_scan_delay: 10)),
        5 => Template.new(level: 5, name: "insane", **DEFAULTS.merge(min_rtt_timeout: 50, max_rtt_timeout: 300, initial_rtt_timeout: 250, max_retries: 2, host_timeout: 900_000, max_scan_delay: 5))
      }.freeze

      NAME_INDEX = TEMPLATES.each_with_object({}) do |(_, template), memo|
        memo[template.name] = template
        memo["t#{template.level}"] = template
      end.freeze

      def self.get(level)
        TEMPLATES.fetch(level.to_i, TEMPLATES.fetch(3))
      end

      def self.from_name(value)
        key = value.to_s.strip.downcase
        NAME_INDEX.fetch(key, get(3))
      end
    end
  end
end
