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
      class WindowScan < BaseScan
        def scan_name
          "TCP Window Scan"
        end

        def scan_description
          "ACK scan variant. Differentiates open/closed on systems that advertise non-zero RST window."
        end

        def probe(host, port)
          response, retries = with_retries do
            @context.tcp_prober.send_probe(host: host, port: port, flags: %i[ack], timeout: rtt_timeout)
          end
          state = if response[:reply] == :rst && response[:window].to_i.positive?
                    :open
                  elsif response[:reply] == :rst
                    :closed
                  else
                    :filtered
                  end
          build_result(port: port, proto: :tcp, state: state, service: service_name(port, :tcp), retries: retries)
        end
      end
    end
  end
end
