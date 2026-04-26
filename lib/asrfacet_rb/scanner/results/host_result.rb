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
      class HostResult
        attr_accessor :host, :up, :ports, :os, :os_accuracy, :os_cpe

        def initialize(host:, up: false, ports: [], os: nil, os_accuracy: nil, os_cpe: nil)
          @host = host
          @up = up
          @ports = Array(ports)
          @os = os
          @os_accuracy = os_accuracy
          @os_cpe = os_cpe
        end

        def add_port(port_result)
          @ports << port_result
          port_result
        end

        def open_ports
          @ports.select(&:open?)
        end

        def filtered_ports
          @ports.select(&:filtered?)
        end

        def closed_ports
          @ports.select { |entry| entry.state == :closed }
        end

        def to_h
          {
            host: host,
            up: up,
            ports: ports.map(&:to_h),
            os: os,
            os_accuracy: os_accuracy,
            os_cpe: os_cpe
          }
        end
      end
    end
  end
end
