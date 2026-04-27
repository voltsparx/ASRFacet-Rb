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
      class XmasScan < BaseScan
        def scan_name
          "TCP XMAS Scan"
        end

        def scan_description
          "FIN+PSH+URG set. Named for lit-up packet. Stealthy on non-Windows. Bypasses some ACLs."
        end

        def probe(host, port)
          response, retries = with_retries do
            @context.tcp_prober.send_probe(host: host, port: port, flags: %i[fin psh urg], timeout: rtt_timeout)
          end
          state = if response[:reply] == :rst
                    :closed
                  elsif response[:reply] == :icmp_type_3
                    :filtered
                  else
                    :open_filtered
                  end
          build_result(port: port, proto: :tcp, state: state, service: service_name(port, :tcp), retries: retries)
        end
      end
    end
  end
end
