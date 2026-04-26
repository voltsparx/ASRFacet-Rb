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

require "net/http"
require "openssl"
require "set"
require "uri"

module ASRFacet
  module Passive
    class BaseSource
      include ASRFacet::Core::PluginSDK

      attr_writer :logger, :http_client, :event_bus, :config

      def self.plugin_type
        :passive_source
      rescue ASRFacet::PluginError
        :passive_source
      end

      def name
        raise NotImplementedError, "Subclasses must implement #name"
      end

      def run(_domain, _api_keys = {})
        raise NotImplementedError, "Subclasses must implement #run"
      end

      protected

      def fetch(url, headers: {}, timeout: 10)
        uri = URI.parse(url.to_s)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == "https"
        http.open_timeout = timeout
        http.read_timeout = timeout
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE

        request = Net::HTTP::Get.new(uri.request_uri)
        headers.each { |key, value| request[key] = value }

        http.request(request).body
      rescue URI::InvalidURIError, Net::OpenTimeout, Net::ReadTimeout, OpenSSL::SSL::SSLError, SocketError, SystemCallError => e
        @logger&.warn(event: :source_fetch_error, source: name, error: e.message) if defined?(@logger)
        raise ASRFacet::SourceError, e.message
      rescue IOError => e
        raise ASRFacet::NetworkError, e.message
      rescue ArgumentError => e
        raise ASRFacet::ParseError, e.message
      rescue ASRFacet::Error
        nil
      end
    end
  end
end
