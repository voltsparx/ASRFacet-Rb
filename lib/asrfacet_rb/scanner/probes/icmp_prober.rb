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
      class ICMPProber
        def initialize(adapter: nil)
          @adapter = adapter
        end

        def echo(host:, timeout:)
          return @adapter.call(host: host, timeout: timeout) if @adapter

          socket = Socket.tcp(host, 80, connect_timeout: timeout)
          socket.close
          true
        rescue Errno::ECONNREFUSED
          true
        rescue Errno::ETIMEDOUT, Errno::EHOSTUNREACH, Errno::ENETUNREACH, IOError, SystemCallError
          false
        end
      end
    end
  end
end
