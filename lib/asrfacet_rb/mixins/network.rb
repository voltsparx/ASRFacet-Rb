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

require "openssl"
require "resolv"
require "socket"
require "timeout"
require "whois"

module ASRFacet
  module Mixins
    module Network
      def tcp_open?(host, port, timeout: 3)
        socket = nil
        Timeout.timeout(timeout) do
          socket = TCPSocket.new(host, port)
          true
        end
      rescue StandardError
        false
      ensure
        socket&.close rescue nil
      end

      def dns_lookup(hostname)
        Resolv.getaddresses(hostname.to_s)
      rescue StandardError
        []
      end

      def reverse_dns(ip)
        Resolv.getname(ip.to_s)
      rescue StandardError
        nil
      end

      def whois_lookup(domain)
        Whois.whois(domain.to_s)
      rescue StandardError
        nil
      end

      def ssl_cert(host, port: 443, timeout: 5)
        tcp_socket = nil
        ssl_socket = nil
        Timeout.timeout(timeout) do
          tcp_socket = TCPSocket.new(host, port)
          context = OpenSSL::SSL::SSLContext.new
          context.verify_mode = OpenSSL::SSL::VERIFY_NONE
          ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, context)
          ssl_socket.hostname = host if ssl_socket.respond_to?(:hostname=)
          ssl_socket.connect
          ssl_socket.peer_cert
        end
      rescue StandardError
        nil
      ensure
        ssl_socket&.sysclose rescue nil
        tcp_socket&.close rescue nil
      end
    end
  end
end
