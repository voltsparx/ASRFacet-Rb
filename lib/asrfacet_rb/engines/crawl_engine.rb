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
require "set"
require "time"
require "uri"

module ASRFacet
  module Engines
    class CrawlEngine
      INTERESTING_EXTENSIONS = %w[.bak .sql .zip .log .old .backup .conf .tar .gz].freeze

      def initialize(target = nil, options = {}, client: ASRFacet::HTTP::RetryableClient.new)
        @target = target
        @options = options || {}
        @client = client
      end

      def run(start_url = @target, max_depth: 2, max_pages: 100)
        data = crawl(start_url, max_depth: max_depth, max_pages: max_pages)
        {
          engine: "crawl_engine",
          target: start_url.to_s,
          timestamp: Time.now.iso8601,
          status: data[:pages_crawled].empty? ? :failed : :success,
          data: data,
          errors: []
        }
      rescue StandardError => e
        { engine: "crawl_engine", target: start_url.to_s, timestamp: Time.now.iso8601, status: :failed, data: empty_result, errors: [e.message] }
      end

      def crawl(start_url, max_depth: 2, max_pages: 100)
        start_uri = URI.parse(start_url.to_s)
        return empty_result if start_uri.host.to_s.empty?

        queue = [[start_uri.to_s, 0]]
        visited = Set.new
        links = Set.new
        forms = []
        scripts = Set.new
        comments = Set.new
        interesting_files = Set.new

        until queue.empty? || visited.size >= max_pages
          current_url, depth = queue.shift
          next if visited.include?(current_url)

          visited << current_url
          response = @client.get(current_url)
          next if response.nil?

          body = response.body.to_s
          doc = Nokogiri::HTML(body)

          doc.xpath("//comment()").each do |comment|
            text = comment.text.to_s.strip
            comments << text unless text.empty?
          end

          doc.css("script").each do |script|
            source = absolutize(current_url, script["src"])
            scripts << source if source
          end

          doc.css("form").each do |form|
            method = form["method"].to_s.upcase
            forms << {
              page: current_url,
              action: absolutize(current_url, form["action"]) || current_url,
              method: method.empty? ? "GET" : method,
              inputs: form.css("input, textarea, select").map { |field| field["name"].to_s }.reject(&:empty?)
            }
          rescue StandardError
            nil
          end

          doc.css("a[href]").each do |anchor|
            link = absolutize(current_url, anchor["href"])
            next unless same_host?(start_uri.host, link)

            links << link
            interesting_files << link if interesting_extension?(link)
            queue << [link, depth + 1] if depth < max_depth && !visited.include?(link)
          rescue StandardError
            nil
          end
        end

        {
          pages_crawled: visited.to_a.sort,
          links: links.to_a.sort,
          forms: forms,
          scripts: scripts.to_a.sort,
          comments: comments.to_a.sort,
          interesting_files: interesting_files.to_a.sort
        }
      rescue StandardError
        empty_result
      end

      private

      def empty_result
        { pages_crawled: [], links: [], forms: [], scripts: [], comments: [], interesting_files: [] }
      end

      def absolutize(base_url, target)
        return nil if target.to_s.strip.empty?

        uri = URI.join(base_url, target.to_s)
        uri.fragment = nil
        uri.to_s
      rescue StandardError
        nil
      end

      def same_host?(host, url)
        URI.parse(url.to_s).host.to_s.casecmp?(host.to_s)
      rescue StandardError
        false
      end

      def interesting_extension?(url)
        path = URI.parse(url.to_s).path.to_s.downcase
        INTERESTING_EXTENSIONS.any? { |extension| path.end_with?(extension) }
      rescue StandardError
        false
      end
    end
  end
end
