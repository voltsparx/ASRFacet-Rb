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
require "time"

module ASRFacet
  module Engines
    class HttpEngine
    TECH_FINGERPRINTS = {
      "WordPress" => /wp-content|wp-includes|wordpress/i,
      "Drupal" => /drupal-settings-json|sites\/default|drupal/i,
      "Joomla" => /joomla!|com_content|\/media\/system\/js\//i,
      "Laravel" => /laravel_session|x-powered-by:\s*php|csrf-token/i,
      "Django" => /csrftoken|django/i,
      "Rails" => /_rails_session|csrf-param|ruby on rails/i,
      "Express" => /x-powered-by:\s*express/i,
      "Nginx" => /server:\s*nginx/i,
      "Apache" => /server:\s*apache/i,
      "IIS" => /server:\s*microsoft-iis/i,
      "Cloudflare" => /cf-ray|cloudflare/i,
      "jQuery" => /jquery(?:\.min)?\.js|jQuery/i,
      "React" => /react(?:dom)?|data-reactroot/i,
      "Vue.js" => /vue(?:\.runtime)?(?:\.min)?\.js|data-v-/i,
      "Angular" => /ng-version|angular(?:\.min)?\.js/i,
      "Bootstrap" => /bootstrap(?:\.min)?\.(?:css|js)/i,
      "PHP" => /x-powered-by:\s*php|php(?:\/|\s)/i,
      "ASP.NET" => /x-aspnet-version|__viewstate|asp\.net/i
    }.freeze

    SECURITY_HEADERS = [
      "Strict-Transport-Security",
      "Content-Security-Policy",
      "X-Frame-Options",
      "X-Content-Type-Options",
      "Referrer-Policy",
      "Permissions-Policy",
      "X-XSS-Protection"
    ].freeze

    CDN_SIGNATURES = {
      "Cloudflare" => /cloudflare|cf-ray|cf-cache-status/i,
      "Fastly" => /fastly|x-served-by|x-cache/i,
      "Akamai" => /akamai|akamaighost|x-akamai/i,
      "CloudFront" => /cloudfront|x-amz-cf-id/i,
      "Sucuri" => /sucuri/i,
      "Incapsula" => /incap_ses|visid_incap|incapsula/i
    }.freeze

    INTERESTING_PATHS = %w[
      /.git/HEAD /.env /.svn/entries /.hg/store /phpinfo.php /admin /admin/login
      /administrator /login /dashboard /user/login /server-status /actuator /actuator/health
      /swagger /swagger-ui /swagger-ui.html /api-docs /openapi.json /robots.txt /sitemap.xml
      /crossdomain.xml /backup.zip /backup.tar.gz /backup.sql /db.sql /dump.sql /config.php.bak
      /config.bak /web.config.bak /.DS_Store /test /old /dev /staging /jenkins /gitlab
      /.well-known/security.txt /console /metrics /debug /status /backup.old
    ].freeze

      def initialize(target = nil, options = {}, client: ASRFacet::HTTP::RetryableClient.new)
        @target = target
        @options = options || {}
        @client = client
      end

      def run(host = @target)
        data = probe(host)
        {
          engine: "http_engine",
          target: host.to_s,
          timestamp: Time.now.iso8601,
          status: data.nil? ? :failed : :success,
          data: data || {},
          errors: data.nil? ? ["HTTP probe failed"] : []
        }
      rescue StandardError => e
        { engine: "http_engine", target: host.to_s, timestamp: Time.now.iso8601, status: :failed, data: {}, errors: [e.message] }
      end

      def probe(host)
        %w[https http].each do |scheme|
          url = "#{scheme}://#{host}"
          response = @client.get(url)
          next if response.nil?

          body = response.body.to_s
          headers = response.each_header.to_h
          return {
            host: host,
            url: url,
            status: response.code.to_i,
            status_code: response.code.to_i,
            title: extract_title(body),
            headers: headers,
            technologies: detect_technologies(headers, body),
            security_headers: extract_security_headers(headers),
            cdn: detect_cdn(headers),
            interesting_paths: check_paths(host, scheme: scheme),
            body_preview: body[0, 50_000]
          }
        rescue StandardError
          next
        end
        nil
      rescue StandardError
        nil
      end

      def check_paths(host, scheme: "https")
        base_url = "#{scheme}://#{host}"
        results = []
        mutex = Mutex.new
        pool = ASRFacet::ThreadPool.new(20)

        INTERESTING_PATHS.each do |path|
          pool.enqueue do
            response = @client.get("#{base_url}#{path}")
            next if response.nil?

            status = response.code.to_i
            next if status == 404

            mutex.synchronize do
              results << {
                path: path,
                status: status,
                size: response.body.to_s.bytesize
              }
            end
          rescue StandardError
            nil
          end
        end

        pool.wait
        results.sort_by { |entry| [entry[:status], entry[:path]] }
      rescue StandardError
        []
      end

      private

      def extract_title(body)
        Nokogiri::HTML(body.to_s).at("title")&.text.to_s.strip
      rescue StandardError
        ""
      end

      def detect_technologies(headers, body)
        cookie_string = Array(headers["set-cookie"]).join(" ")
        combined = "#{format_headers(headers)}\n#{cookie_string}\n#{body.to_s[0, 50_000]}"

        TECH_FINGERPRINTS.each_with_object([]) do |(name, pattern), memo|
          memo << name if combined.match?(pattern)
        end
      rescue StandardError
        []
      end

      def extract_security_headers(headers)
        SECURITY_HEADERS.each_with_object({}) do |header, memo|
          value = headers[header.downcase] || headers[header]
          memo[header] = value.to_s.empty? ? false : value
        end
      rescue StandardError
        {}
      end

      def detect_cdn(headers)
        formatted = format_headers(headers)
        CDN_SIGNATURES.each do |name, pattern|
          return name if formatted.match?(pattern)
        end
        nil
      rescue StandardError
        nil
      end

      def format_headers(headers)
        headers.map { |key, value| "#{key}: #{value}" }.join("\n")
      rescue StandardError
        ""
      end
    end
  end
end
