# frozen_string_literal: true
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

require_relative "base_source"

module ASRFacet
  module Sources
    class SecuritytrailsSource < BaseSource
      def name = :securitytrails

      def requires_key? = true

      def fetch(domain)
        return [] unless available?

        url = "https://api.securitytrails.com/v1/domain/#{domain}/subdomains?children_only=false&include_inactive=true"
        data = get_json(url, headers: { "APIKEY" => api_key })
        return [] if data.nil?

        Array(data["subdomains"]).map { |subdomain| "#{subdomain}.#{domain}" }
      end
    end
  end
end
