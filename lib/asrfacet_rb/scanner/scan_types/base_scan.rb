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
      class BaseScan
        def initialize(context, sleep_proc: ->(duration) { sleep(duration) })
          @context = context
          @sleep_proc = sleep_proc
        end

        def probe(_host, _port)
          raise NotImplementedError
        end

        def scan_name
          self.class.name.split("::").last.gsub(/Scan\z/, "").downcase
        end

        def sleep_delay
          @context.timing.scan_delay.to_f / 1000.0
        end

        def rtt_timeout
          @context.timing.initial_rtt_timeout.to_f / 1000.0
        end

        def with_retries(max: @context.timing.max_retries)
          retries = 0
          begin
            result = yield(retries)
            return [result, retries]
          rescue Errno::ETIMEDOUT, Errno::EHOSTUNREACH, Errno::ENETUNREACH, IOError, SystemCallError
            raise if retries >= max.to_i

            retries += 1
            @sleep_proc.call(sleep_delay) if sleep_delay.positive?
            retry
          end
        end

        protected

        def build_result(port:, proto:, state:, service: nil, version: nil, extra: nil, cpe: nil, banner: nil, rtt: nil, retries: 0)
          ASRFacet::Scanner::Results::PortResult.new(
            port: port,
            proto: proto,
            state: state,
            service: service,
            version: version,
            extra: extra,
            cpe: cpe,
            banner: banner,
            rtt: rtt,
            retries: retries
          )
        end

        def service_name(port, proto)
          @context.probe_db.service_for(port, proto)
        end
      end
    end
  end
end
