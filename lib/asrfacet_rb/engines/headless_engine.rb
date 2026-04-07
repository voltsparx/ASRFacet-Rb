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
require "uri"

module ASRFacet
  module Engines
    class HeadlessEngine
      FERRUM_AVAILABLE = begin
        require "ferrum"
        true
      rescue LoadError
        false
      end

      attr_writer :logger, :http_client, :event_bus, :config

      def initialize(options = {})
        @timeout = options[:timeout] || 15
        @wait = options[:wait] || 2
        @available = FERRUM_AVAILABLE
      rescue StandardError
        @timeout = 15
        @wait = 2
        @available = false
      end

      def self.plugin_type
        :engine
      rescue StandardError
        :engine
      end

      def available?
        @available
      rescue StandardError
        false
      end

      def probe(url)
        unless available?
          ASRFacet::Core::ThreadSafe.print_warning("Ferrum is not available; skipping headless rendering.")
          return nil
        end

        browser = Ferrum::Browser.new(
          headless: true,
          timeout: @timeout,
          browser_options: { "no-sandbox" => nil, "disable-gpu" => nil }
        )
        browser.goto(url.to_s)
        sleep(@wait.to_f)

        rendered_html = browser.body.to_s
        document = Nokogiri::HTML(rendered_html)
        network_requests = fetch_network_requests(browser)
        console_messages = fetch_console_messages(browser)
        {
          url: url.to_s,
          title: browser.current_title.to_s,
          final_url: browser.current_url.to_s,
          rendered_html: rendered_html,
          rendered_links: document.css("a[href]").filter_map { |node| absolutize(browser.current_url.to_s, node["href"]) }.uniq.sort,
          forms: document.css("form").map { |form| parse_form(browser.current_url.to_s, form) }.compact,
          network_requests: network_requests,
          js_errors: console_messages.select { |message| message.respond_to?(:type) && message.type.to_s == "error" }.map { |message| message.respond_to?(:text) ? message.text.to_s : message.to_s },
          spa_endpoints: extract_spa_endpoints(network_requests),
          rendered: true
        }
      rescue StandardError
        nil
      ensure
        browser&.quit rescue nil
      end

      def extract_spa_endpoints(network_requests)
        Array(network_requests).filter_map do |request|
          entry = request.is_a?(Hash) ? request : {}
          url = entry[:url].to_s
          method = entry[:method].to_s.upcase
          next if url.empty?

          uri = URI.parse(url)
          path = uri.path.to_s
          next unless path.start_with?("/api/", "/v1/", "/v2/", "/graphql", "/rest/") || %w[POST PUT PATCH DELETE].include?(method)

          url
        rescue StandardError
          nil
        end.uniq.sort
      rescue StandardError
        []
      end

      private

      def fetch_network_requests(browser)
        Array(browser.network.traffic).map do |request|
          {
            url: request.url.to_s,
            method: request.respond_to?(:method) ? request.method.to_s.upcase : "GET"
          }
        rescue StandardError
          nil
        end.compact
      rescue StandardError
        []
      end

      def fetch_console_messages(browser)
        Array(browser.console_messages)
      rescue StandardError
        []
      end

      def parse_form(base_url, form)
        {
          action: absolutize(base_url, form["action"]) || base_url.to_s,
          method: form["method"].to_s.upcase.empty? ? "GET" : form["method"].to_s.upcase,
          inputs: form.css("input, textarea, select").map { |field| field["name"].to_s }.reject(&:empty?)
        }
      rescue StandardError
        nil
      end

      def absolutize(base_url, target)
        return nil if target.to_s.strip.empty?

        URI.join(base_url.to_s, target.to_s).to_s
      rescue StandardError
        nil
      end
    end
  end
end
