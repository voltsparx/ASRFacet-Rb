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
        attr_accessor :host, :up, :ports, :os, :os_accuracy, :os_cpe,
                      :os_guesses, :os_vendor, :os_family, :distance,
                      :scan_delay_used, :timing_level_used,
                      :open_tcp_port, :closed_tcp_port

        def initialize(host:, up: false, ports: [], os: nil, os_accuracy: nil, os_cpe: nil,
                       os_guesses: [], os_vendor: nil, os_family: nil, distance: -1,
                       scan_delay_used: 0, timing_level_used: 3, open_tcp_port: -1,
                       closed_tcp_port: -1)
          @host = host
          @up = up
          @ports = Array(ports)
          @os = os
          @os_accuracy = os_accuracy
          @os_cpe = os_cpe
          @os_guesses = Array(os_guesses)
          @os_vendor = os_vendor
          @os_family = os_family
          @distance = distance
          @scan_delay_used = scan_delay_used
          @timing_level_used = timing_level_used
          @open_tcp_port = open_tcp_port
          @closed_tcp_port = closed_tcp_port
        end

        def add_port(port_result)
          @ports << port_result
          if port_result.proto == :tcp && port_result.state == :open && open_tcp_port.to_i <= 0
            @open_tcp_port = port_result.port
          elsif port_result.proto == :tcp && port_result.state == :closed && closed_tcp_port.to_i <= 0
            @closed_tcp_port = port_result.port
          end
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

        def best_os
          Array(os_guesses).first
        end

        def to_h
          {
            host: host,
            up: up,
            ports: ports.map(&:to_h),
            os: os,
            os_accuracy: os_accuracy,
            os_cpe: os_cpe,
            os_guesses: os_guesses,
            os_vendor: os_vendor,
            os_family: os_family,
            distance: distance,
            scan_delay_used: scan_delay_used,
            timing_level_used: timing_level_used,
            open_tcp_port: open_tcp_port,
            closed_tcp_port: closed_tcp_port
          }
        end
      end
    end
  end
end
