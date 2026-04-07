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

require "set"
require "thread"

module ASRFacet::Busters
  class DirBuster < BaseBuster
    def initialize(base_url, wordlist, extensions: [], filter_codes: [404], workers: 40)
      @base_url = base_url.to_s.sub(%r{/+\z}, "")
      @wordlist = wordlist
      @extensions = Array(extensions).map { |entry| entry.to_s.sub(/\A\./, "") }.reject(&:empty?)
      @filter_codes = Array(filter_codes).map(&:to_i)
      @workers = workers.to_i.positive? ? workers.to_i : 40
      @client = ASRFacet::HTTP::RetryableClient.new
      @mutex = Mutex.new
    end

    def run
      results = []
      seen = Set.new
      pool = ASRFacet::ThreadPool.new(@workers)

      File.foreach(@wordlist).lazy.each do |line|
        word = line.to_s.strip
        next if word.empty? || word.start_with?("#")

        candidate_paths(word).each do |path|
          next unless seen.add?(path)

          pool.enqueue do
            response = @client.get("#{@base_url}#{path}")
            next if response.nil?

            status = response.code.to_i
            next if @filter_codes.include?(status)

            body = response.body.to_s
            result = { path: path, status: status, size: body.bytesize, words: body.split(/\s+/).reject(&:empty?).size }
            @mutex.synchronize { results << result }
          rescue StandardError
            nil
          end
        end
      end

      pool.wait
      results.uniq.sort_by { |entry| [entry[:status], entry[:path]] }
    rescue StandardError
      []
    end

    private

    def candidate_paths(word)
      base = word.start_with?("/") ? word : "/#{word}"
      variants = [base]
      @extensions.each do |extension|
        variants << "#{base}.#{extension}"
      end
      variants
    rescue StandardError
      []
    end
  end
end
