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

require "socket"

module ASRFacet
  module Scanner
    module Probes
      class TCPProber
        def initialize(adapter: nil)
          @adapter = adapter
        end

        def raw_socket_capable?
          return @adapter.raw_socket_capable? if @adapter&.respond_to?(:raw_socket_capable?)

          false
        rescue StandardError
          false
        end

        def send_probe(host:, port:, flags:, timeout:)
          return @adapter.call(host: host, port: port, flags: flags, timeout: timeout) if @adapter

          socket = Socket.tcp(host, port, connect_timeout: timeout)
          socket.close
          { reply: :syn_ack, window: 0 }
        rescue Errno::ECONNREFUSED
          { reply: :rst, window: 0 }
        rescue Errno::ETIMEDOUT, Errno::EHOSTUNREACH, Errno::ENETUNREACH, IOError, SystemCallError
          { reply: :timeout, window: 0 }
        end

        def fingerprint(host:, port: 80, timeout:)
          return @adapter.fingerprint(host: host, port: port, timeout: timeout) if @adapter&.respond_to?(:fingerprint)

          socket = Socket.tcp(host, port, connect_timeout: timeout)
          socket.close
          { ttl: 64, window: 29_200, tcp_options: %i[mss sack timestamp nop window_scale], ip_id_sequence: [1, 2, 3], rst_behavior: :rst }
        rescue Errno::ECONNREFUSED
          { ttl: 128, window: 8192, tcp_options: %i[mss nop window_scale], ip_id_sequence: [10, 11, 12], rst_behavior: :rst }
        rescue Errno::ETIMEDOUT, Errno::EHOSTUNREACH, Errno::ENETUNREACH, IOError, SystemCallError
          nil
        end
      end
    end
  end
end
