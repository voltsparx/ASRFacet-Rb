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
    module ScanTypes
      class ConnectScan < BaseScan
        def initialize(context, socket_class: TCPSocket, **options)
          super(context, **options)
          @socket_class = socket_class
        end

        def scan_name
          "TCP Connect Scan"
        end

        def scan_description
          "Full TCP handshake. Logged by target. Use when raw sockets unavailable."
        end

        def probe(host, port)
          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          result, retries = with_retries do
            socket = @socket_class.new(host, port, connect_timeout: rtt_timeout)
            banner = read_banner(socket)
            build_result(port: port, proto: :tcp, state: :open, service: service_name(port, :tcp), banner: banner)
          rescue Errno::ECONNREFUSED
            build_result(port: port, proto: :tcp, state: :closed, service: service_name(port, :tcp))
          rescue Errno::ETIMEDOUT, Errno::EHOSTUNREACH, Errno::ENETUNREACH
            build_result(port: port, proto: :tcp, state: :filtered, service: service_name(port, :tcp))
          ensure
            socket&.close
          end
          result.rtt = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000.0).round(2)
          result.retries = retries
          result
        end

        private

        def read_banner(socket)
          return nil unless socket.is_a?(IO) || socket.respond_to?(:to_io)

          readable = IO.select([socket], nil, nil, 1.0)
          return nil unless readable

          socket.readpartial(1024)
        rescue EOFError, IOError, SystemCallError
          nil
        end
      end
    end
  end
end
