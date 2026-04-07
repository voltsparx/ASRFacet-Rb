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
require "socket"
require "uri"

module ASRFacet
  module HTTP
    class CustomTransport
      def initialize(opts = {})
        options = symbolize_keys(opts)
        @connect_timeout = options[:connect_timeout] || 3
        @read_timeout = options[:read_timeout] || 8
        @verify_ssl = options.key?(:verify_ssl) ? options[:verify_ssl] : false
        @follow_redirects = options.key?(:follow_redirects) ? options[:follow_redirects] : true
        @max_redirects = options[:max_redirects] || 5
      rescue StandardError
        @connect_timeout = 3
        @read_timeout = 8
        @verify_ssl = false
        @follow_redirects = true
        @max_redirects = 5
      end

      def request(url, method: :get, headers: {}, body: nil, redirects_left: nil)
        redirects_left = @max_redirects if redirects_left.nil?
        uri = URI.parse(url.to_s)
        return nil if uri.host.to_s.empty?

        tcp_socket = build_tcp_socket(uri)
        return nil if tcp_socket.nil?

        io = wrap_socket(uri, tcp_socket)
        return nil if io.nil?

        io.write(build_request(method, uri, headers, body))
        io.flush if io.respond_to?(:flush)

        parsed = parse_response(io)
        return nil if parsed.nil?

        response = parsed.merge(
          url: url.to_s,
          redirected: false
        )

        if redirect_response?(response[:status]) && @follow_redirects && redirects_left.to_i.positive?
          location = response.dig(:headers, "location").to_s
          return response if location.empty?

          next_url = URI.join(url.to_s, location).to_s
          redirected = request(next_url, method: method, headers: headers, body: body, redirects_left: redirects_left.to_i - 1)
          return redirected.merge(redirected: true) unless redirected.nil?
        end

        response
      rescue StandardError
        nil
      ensure
        close_socket(io)
        close_socket(tcp_socket)
      end

      def http2_fallback?(response_line)
        response_line.to_s.start_with?("HTTP/2")
      rescue StandardError
        false
      end

      def build_request(method, uri, headers, body)
        normalized_headers = { "Host" => uri.host.to_s, "User-Agent" => "ASRFacet-Rb/#{ASRFacet::VERSION}", "Connection" => "close" }
        symbolize_keys(headers).each do |key, value|
          normalized_headers[header_name(key)] = value
        end
        normalized_body = body.to_s
        normalized_headers["Content-Length"] = normalized_body.bytesize.to_s unless normalized_body.empty?
        path = uri.request_uri.to_s
        path = "/" if path.empty?

        lines = ["#{method.to_s.upcase} #{path} HTTP/1.1"]
        normalized_headers.each do |key, value|
          lines << "#{key}: #{value}"
        end
        lines << ""
        lines << normalized_body
        lines.join("\r\n")
      rescue StandardError
        ""
      end

      def parse_response(socket)
        status_line = socket.gets("\n")
        return nil if status_line.to_s.strip.empty?
        return nil if http2_fallback?(status_line)

        status_match = status_line.match(/\AHTTP\/1\.[01]\s+(\d{3})/)
        return nil if status_match.nil?

        headers = {}
        while (line = socket.gets("\n"))
          stripped = line.to_s.strip
          break if stripped.empty?

          key, value = stripped.split(":", 2)
          next if key.to_s.empty?

          headers[key.to_s.downcase] = value.to_s.strip
        end

        body = if headers["content-length"].to_s.match?(/\A\d+\z/)
                 socket.read(headers["content-length"].to_i).to_s
               else
                 read_until_close(socket)
               end

        {
          status: status_match[1].to_i,
          headers: headers,
          body: body.to_s
        }
      rescue StandardError
        nil
      end

      private

      def build_tcp_socket(uri)
        port = uri.port || (uri.scheme == "https" ? 443 : 80)
        socket = Socket.tcp(uri.host.to_s, port, connect_timeout: @connect_timeout)
        apply_socket_timeouts(socket)
        socket
      rescue StandardError
        nil
      end

      def wrap_socket(uri, tcp_socket)
        return tcp_socket unless uri.scheme == "https"

        context = OpenSSL::SSL::SSLContext.new
        context.verify_mode = @verify_ssl ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE
        ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, context)
        ssl_socket.hostname = uri.host.to_s if ssl_socket.respond_to?(:hostname=)
        ssl_socket.sync_close = true
        ssl_socket.connect
        ssl_socket
      rescue StandardError
        nil
      end

      def apply_socket_timeouts(socket)
        return nil unless socket.respond_to?(:setsockopt)

        seconds = @read_timeout.to_i
        microseconds = ((@read_timeout.to_f - seconds) * 1_000_000).to_i
        packed = [seconds, microseconds].pack("l!l!")
        socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVTIMEO, packed)
        socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_SNDTIMEO, packed)
      rescue StandardError
        nil
      end

      def read_until_close(socket)
        buffer = +""
        loop do
          chunk = socket.readpartial(4096)
          buffer << chunk
        end
      rescue EOFError
        buffer
      rescue StandardError
        buffer
      end

      def redirect_response?(status)
        status.to_i >= 300 && status.to_i < 400
      rescue StandardError
        false
      end

      def close_socket(socket)
        return nil if socket.nil?

        socket.close
      rescue StandardError
        nil
      end

      def symbolize_keys(hash)
        hash.each_with_object({}) do |(key, value), memo|
          memo[key.to_sym] = value
        end
      rescue StandardError
        {}
      end

      def header_name(key)
        key.to_s.split("-").map { |part| part[0].to_s.upcase + part[1..].to_s.downcase }.join("-")
      rescue StandardError
        key.to_s
      end
    end
  end
end
