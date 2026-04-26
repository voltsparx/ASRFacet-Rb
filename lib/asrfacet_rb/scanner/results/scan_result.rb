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
    module Results
      class ScanResult
        attr_accessor :targets, :scan_type, :timing, :started_at, :finished_at, :host_results

        def initialize(targets:, scan_type:, timing:, started_at:, finished_at: nil, host_results: [])
          @targets = Array(targets)
          @scan_type = scan_type.to_sym
          @timing = timing
          @started_at = started_at
          @finished_at = finished_at
          @host_results = Array(host_results)
        end

        def add_host(host_result)
          @host_results << host_result
          host_result
        end

        def elapsed
          return nil unless started_at && finished_at

          finished_at - started_at
        end

        def total_open
          host_results.sum { |host| host.open_ports.count }
        end

        def total_filtered
          host_results.sum { |host| host.filtered_ports.count }
        end

        def to_h
          {
            targets: targets,
            scan_type: scan_type,
            timing: timing.to_h,
            started_at: started_at&.utc&.iso8601,
            finished_at: finished_at&.utc&.iso8601,
            elapsed: elapsed,
            total_open: total_open,
            total_filtered: total_filtered,
            host_results: host_results.map(&:to_h)
          }
        end
      end
    end
  end
end
