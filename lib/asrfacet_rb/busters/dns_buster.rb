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

require "resolv"
require "securerandom"
require "thread"

module ASRFacet::Busters
  class DnsBuster < BaseBuster
    def initialize(domain, wordlist, workers: 100)
      @domain = domain.to_s.downcase
      @wordlist = wordlist
      @workers = workers.to_i.positive? ? workers.to_i : 100
      @mutex = Mutex.new
      @wildcard_ips = detect_wildcard
    end

    def run
      results = []
      pool = ASRFacet::ThreadPool.new(@workers, queue_size: bounded_queue_size(@workers))

      File.foreach(@wordlist).lazy.each do |line|
        word = line.to_s.strip.downcase
        next if word.empty? || word.start_with?("#")

        pool.enqueue do
          hostname = "#{word}.#{@domain}"
          ips = Resolv.getaddresses(hostname).uniq
          filtered_ips = ips - @wildcard_ips
          next if filtered_ips.empty?

          @mutex.synchronize do
            results << { subdomain: hostname, ips: filtered_ips.sort }
          end
        rescue StandardError
          nil
        end
      end

      pool.wait
      results.uniq.sort_by { |entry| entry[:subdomain] }
    rescue StandardError
      []
    end

    private

    def detect_wildcard
      Resolv.getaddresses("#{SecureRandom.hex(12)}.#{@domain}").uniq
    rescue StandardError
      []
    end
  end
end
