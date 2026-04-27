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
    module ScanTypes
      class UdpScan < BaseScan
        def scan_name
          "UDP Scan"
        end

        def scan_description
          "Detects UDP services often missed. Slower than TCP scans. Use -sU."
        end

        def probe(host, port)
          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          response, retries = with_retries do
            @context.udp_prober.send_probe(host: host, port: port, payload: "", timeout: rtt_timeout)
          end
          state = case response[:reply]
                  when :udp then :open
                  when :icmp_port_unreachable then :closed
                  when :icmp_type_3 then :filtered
                  else :open_filtered
                  end
          build_result(
            port: port,
            proto: :udp,
            state: state,
            service: service_name(port, :udp),
            banner: response[:data],
            rtt: ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000.0).round(2),
            retries: retries
          )
        end
      end
    end
  end
end
