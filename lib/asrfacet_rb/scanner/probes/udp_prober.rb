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
      class UDPProber
        def initialize(adapter: nil, socket_class: UDPSocket)
          @adapter = adapter
          @socket_class = socket_class
        end

        def send_probe(host:, port:, payload:, timeout:)
          return @adapter.call(host: host, port: port, payload: payload, timeout: timeout) if @adapter

          socket = @socket_class.new
          socket.connect(host, port)
          socket.write(payload.to_s)
          readable = IO.select([socket], nil, nil, timeout)
          return { reply: :timeout } unless readable

          data = socket.recvfrom_nonblock(4096).first
          { reply: :udp, data: data }
        rescue IO::WaitReadable
          { reply: :timeout }
        rescue Errno::ECONNREFUSED
          { reply: :icmp_port_unreachable }
        rescue Errno::ETIMEDOUT, IOError, SystemCallError
          { reply: :timeout }
        ensure
          socket&.close
        end
      end
    end
  end
end
