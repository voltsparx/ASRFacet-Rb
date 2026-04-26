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

require "nokogiri"

module ASRFacet
  module Intelligence
    module Enrichment
      class HttpEnricher
        TECH_PATTERNS = {
          "WordPress" => /wp-content|wp-includes|wordpress/i,
          "Drupal" => /drupal|sites\/default/i,
          "React" => /react|data-reactroot/i,
          "Angular" => /ng-version|angular/i,
          "Django" => /csrftoken|django/i,
          "Rails" => /ruby on rails|\brails\b|_rails_session|csrf-param/i,
          "Laravel" => /laravel|laravel_session|x-powered-by:\s*php/i,
          "Spring" => /spring|jsessionid/i,
          "ASP.NET" => /x-aspnet-version|__viewstate|asp\.net/i,
          "Vue" => /vue(?:\.runtime)?(?:\.min)?\.js|data-v-|\bvue\b/i
        }.freeze

        def initialize(http_client: ASRFacet::HTTP::RetryableClient.new, logger: nil, max_redirects: 5)
          @http_client = http_client
          @logger = logger
          @max_redirects = max_redirects.to_i.positive? ? max_redirects.to_i : 5
        end

        def enrich(host, graph:, ports: [80, 443])
          fqdn = host.to_s.downcase
          host_asset = graph.add_asset(
            ASRFacet::Intelligence::OAM.make(type: :fqdn, value: fqdn, source: "http_enricher", properties: {})
          )

          responses = endpoints_for(fqdn, ports).filter_map do |endpoint|
            response = @http_client.get(endpoint[:url], opts: { follow_redirects: true, max_redirects: @max_redirects })
            next if response.nil?

            headers = headers_hash(response)
            body = response.body.to_s
            technologies = detect_technologies(headers, body)
            robots = check_auxiliary(endpoint[:base_url], "/robots.txt")
            sitemap = check_auxiliary(endpoint[:base_url], "/sitemap.xml")

            graph.add_asset(
              ASRFacet::Intelligence::OAM.make(
                type: :fqdn,
                value: fqdn,
                source: "http_enricher",
                properties: {
                  title: extract_title(body),
                  server: headers["server"].to_s,
                  x_powered_by: headers["x-powered-by"].to_s,
                  robots: robots,
                  sitemap: sitemap
                }
              )
            )

            technologies.each do |technology|
              tech_asset = graph.add_asset(
                ASRFacet::Intelligence::OAM.make(type: :technology, value: technology, source: "http_enricher", properties: { port: endpoint[:port] })
              )
              graph.add_relation(from: host_asset, to: tech_asset, type: :contains, source: "http_enricher", properties: { port: endpoint[:port] })
            end

            {
              url: endpoint[:url],
              port: endpoint[:port],
              status: response.code.to_i,
              title: extract_title(body),
              server: headers["server"].to_s,
              x_powered_by: headers["x-powered-by"].to_s,
              technologies: technologies,
              robots: robots,
              sitemap: sitemap
            }
          end

          {
            host: fqdn,
            responses: responses,
            technologies: responses.flat_map { |entry| entry[:technologies] }.uniq.sort
          }
        rescue StandardError => e
          log_warning("HTTP enrichment failed for #{host}: #{e.message}")
          {}
        end

        private

        def endpoints_for(host, ports)
          Array(ports).uniq.map do |port|
            port_number = port.to_i
            scheme = https_port?(port_number) ? "https" : "http"
            authority = if [80, 443].include?(port_number)
                          host
                        else
                          "#{host}:#{port_number}"
                        end
            base_url = "#{scheme}://#{authority}"
            { port: port_number, base_url: base_url, url: "#{base_url}/" }
          end
        end

        def https_port?(port)
          [443, 8443].include?(port)
        end

        def headers_hash(response)
          response.each_header.each_with_object({}) do |(key, value), memo|
            memo[key.to_s.downcase] = value.to_s
          end
        rescue StandardError
          {}
        end

        def extract_title(body)
          Nokogiri::HTML(body.to_s).at("title")&.text.to_s.strip
        rescue StandardError
          ""
        end

        def detect_technologies(headers, body)
          combined = "#{headers.map { |key, value| "#{key}: #{value}" }.join("\n")}\n#{body}"
          TECH_PATTERNS.each_with_object([]) do |(name, pattern), memo|
            memo << name if combined.match?(pattern)
          end
        rescue StandardError
          []
        end

        def check_auxiliary(base_url, path)
          response = @http_client.get("#{base_url}#{path}", opts: { follow_redirects: true, max_redirects: @max_redirects })
          response && response.code.to_i.between?(200, 299)
        rescue StandardError
          false
        end

        def log_warning(message)
          if @logger&.respond_to?(:warn)
            @logger.warn(message)
          elsif @logger&.respond_to?(:print_warning)
            @logger.print_warning(message)
          end
        rescue StandardError
          nil
        end
      end
    end
  end
end
