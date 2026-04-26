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
        RAW_FLAG_MAP = %i[syn ack fin psh urg rst ecn cwr].freeze

        def initialize(adapter: nil, raw_adapter: nil, platform: ASRFacet::Scanner::Platform)
          @adapter = adapter
          @raw_adapter = raw_adapter
          @platform = platform
        end

        def raw_socket_capable?
          return @raw_adapter.raw_socket_capable? if @raw_adapter&.respond_to?(:raw_socket_capable?)
          return @adapter.raw_socket_capable? if @adapter&.respond_to?(:raw_socket_capable?)

          false
        rescue StandardError
          false
        end

        def send_probe(host:, port:, flags:, timeout:)
          if use_raw_backend?(flags)
            return @raw_adapter.call(host: host, port: port, flags: flags, timeout: timeout)
          end
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

        private

        def use_raw_backend?(flags)
          return false unless @raw_adapter
          return false unless raw_socket_capable?
          return false unless @platform.elevated?

          Array(flags).any? { |flag| RAW_FLAG_MAP.include?(flag.to_sym) }
        rescue StandardError
          false
        end
      end
    end
  end
end
