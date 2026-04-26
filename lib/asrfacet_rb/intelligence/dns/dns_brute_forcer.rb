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

require "set"
require_relative "dns_permutator"
require_relative "dns_wildcard"

module ASRFacet
  module Intelligence
    module Dns
      class DnsBruteForcer
        DEFAULT_MAX_PARALLELISM = 50
        DEFAULT_WORDLIST = File.expand_path(File.join(__dir__, "..", "..", "..", "..", "wordlists", "subdomains_small.txt")).freeze

        def initialize(resolver:, wildcard_detector: nil, permutator: nil, event_bus: nil, logger: nil, max_parallelism: DEFAULT_MAX_PARALLELISM, wordlist_path: nil)
          @resolver = resolver
          @wildcard_detector = wildcard_detector || DnsWildcard.new(resolver: resolver, logger: logger)
          @permutator = permutator || DnsPermutator.new
          @event_bus = event_bus
          @logger = logger
          @max_parallelism = max_parallelism.to_i.positive? ? max_parallelism.to_i : DEFAULT_MAX_PARALLELISM
          @wordlist_path = wordlist_path || DEFAULT_WORDLIST
        end

        def run(domain, discovered_subdomains = [])
          target = domain.to_s.downcase
          @wildcard_detector.detect(target)
          candidates = candidate_list(target, discovered_subdomains)
          results = Set.new
          mutex = Mutex.new
          pool = ASRFacet::ThreadPool.new(@max_parallelism)

          candidates.each do |fqdn|
            pool.enqueue(label: fqdn) do
              next unless discovered?(target, fqdn)

              mutex.synchronize { results << fqdn }
              emit_subdomain(target, fqdn)
            end
          end

          pool.wait
          results.to_a.sort
        end

        private

        def candidate_list(domain, discovered_subdomains)
          built_in = load_wordlist.map { |label| "#{label}.#{domain}" }
          permutations = @permutator.generate(discovered_subdomains, domain)
          (built_in + permutations).map(&:downcase).uniq.sort
        end

        def load_wordlist
          return [] unless File.file?(@wordlist_path)

          File.readlines(@wordlist_path, chomp: true)
              .map(&:strip)
              .reject(&:empty?)
              .uniq
        rescue Errno::EACCES, Errno::ENOENT, IOError
          []
        end

        def discovered?(domain, fqdn)
          responses = @resolver.resolve_types(fqdn, %i[a aaaa cname])
          answers = responses.values.flat_map { |response| Array(response[:answers]) }
          return false if answers.empty?

          @wildcard_detector.filter(domain, fqdn)
        rescue StandardError
          false
        end

        def emit_subdomain(domain, fqdn)
          return if @event_bus.nil?

          @event_bus.emit(
            :subdomain,
            {
              host: fqdn,
              parent: domain,
              data: { source: "dns_brute_forcer" }
            },
            dispatch_now: true
          )
        rescue StandardError
          nil
        end
      end
    end
  end
end
