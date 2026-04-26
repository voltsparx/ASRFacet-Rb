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

require "concurrent"
require "ipaddr"
require "resolv"

module ASRFacet
  module Intelligence
    module Dns
      class DnsResolver
        DEFAULT_PUBLIC_RESOLVERS = %w[
          8.8.8.8
          1.1.1.1
          9.9.9.9
          208.67.222.222
        ].freeze

        DEFAULT_PUBLIC_QPS = 5.0
        DEFAULT_TRUSTED_QPS = 15.0
        DEFAULT_TIMEOUT = 2
        DEFAULT_MAX_ATTEMPTS = 10
        INITIAL_RELIABILITY = 1.0

        SUBRE = "(([a-zA-Z0-9]{1}|[_a-zA-Z0-9]{1}[_a-zA-Z0-9-]{0,61}[a-zA-Z0-9]{1})[.]{1})+".freeze

        RECORD_TYPES = {
          a: Resolv::DNS::Resource::IN::A,
          aaaa: Resolv::DNS::Resource::IN::AAAA,
          cname: Resolv::DNS::Resource::IN::CNAME,
          mx: Resolv::DNS::Resource::IN::MX,
          ns: Resolv::DNS::Resource::IN::NS,
          txt: Resolv::DNS::Resource::IN::TXT,
          srv: Resolv::DNS::Resource::IN::SRV,
          soa: Resolv::DNS::Resource::IN::SOA,
          ptr: Resolv::DNS::Resource::IN::PTR
        }.freeze

        attr_reader :trusted_resolvers

        def initialize(trusted_resolvers: [], timeout: DEFAULT_TIMEOUT, max_attempts: DEFAULT_MAX_ATTEMPTS, dns_factory: nil, clock: nil, sleeper: nil, logger: nil)
          @trusted_resolvers = Array(trusted_resolvers).map { |resolver| resolver.to_s.strip }.reject(&:empty?).uniq
          @resolvers = (@trusted_resolvers + DEFAULT_PUBLIC_RESOLVERS).uniq.freeze
          @timeout = timeout.to_i.positive? ? timeout.to_i : DEFAULT_TIMEOUT
          @max_attempts = max_attempts.to_i.positive? ? max_attempts.to_i : DEFAULT_MAX_ATTEMPTS
          @dns_factory = dns_factory || method(:default_dns_factory)
          @clock = clock || -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }
          @sleeper = sleeper || ->(duration) { sleep(duration) }
          @logger = logger
          @resolver_index = Concurrent::AtomicFixnum.new(0)
          @last_query_at = Concurrent::Map.new
          @resolver_mutexes = Concurrent::Map.new
          @reliability = Concurrent::Map.new
          @resolvers.each { |resolver| @reliability[resolver] = INITIAL_RELIABILITY }
        end

        def resolve(name, type)
          record_type = normalize_record_type(type)
          fqdn = sanitize_name(name)
          query_name = record_type == :ptr ? ptr_name_for(fqdn) : fqdn
          attempts = 0
          errors = []

          @max_attempts.times do |attempt|
            resolver = next_resolver
            attempts += 1
            throttle(resolver)

            response = query_resolver(resolver, query_name, record_type)
            if response[:status] == :success && response[:answers].any?
              mark_success(resolver)
              return {
                name: fqdn,
                query_name: query_name,
                type: record_type,
                resolver: resolver,
                status: :success,
                attempts: attempts,
                answers: response[:answers],
                ttl: response[:answers].map { |entry| entry[:ttl] }.compact.min,
                errors: errors
              }
            end

            mark_failure(resolver, response[:retriable])
            errors << { resolver: resolver, error: response[:error].to_s, status: response[:status] }
            next unless response[:retriable]
            next if attempt + 1 >= @max_attempts

            @sleeper.call(backoff_duration(attempt))
          end

          {
            name: fqdn,
            query_name: query_name,
            type: record_type,
            resolver: nil,
            status: :failed,
            attempts: attempts,
            answers: [],
            ttl: nil,
            errors: errors
          }
        end

        def resolve_types(name, types = RECORD_TYPES.keys)
          Array(types).each_with_object({}) do |type, memo|
            memo[type.to_sym] = resolve(name, type)
          end
        end

        def reliability_scores
          @reliability.each_pair.each_with_object({}) do |(resolver, score), memo|
            memo[resolver] = score.to_f.round(3)
          end
        end

        def subdomain_regex(domain)
          Regexp.new("#{SUBRE}#{Regexp.escape(sanitize_name(domain))}")
        end

        private

        def normalize_record_type(type)
          record_type = type.to_s.downcase.to_sym
          raise ASRFacet::ParseError, "Unsupported DNS record type: #{type}" unless RECORD_TYPES.key?(record_type)

          record_type
        end

        def sanitize_name(name)
          name.to_s.strip.downcase.sub(/\.+\z/, "")
        end

        def ptr_name_for(value)
          ip = IPAddr.new(value.to_s)
          if ip.ipv4?
            "#{reverse_ip(ip.to_s)}.in-addr.arpa"
          else
            "#{ipv6_nibble_format(ip.to_s)}.ip6.arpa"
          end
        rescue IPAddr::InvalidAddressError
          sanitize_name(value)
        end

        def reverse_ip(ip)
          ip.to_s.split(".").reverse.join(".")
        end

        def ipv6_nibble_format(ip)
          expanded = IPAddr.new(ip).hton.unpack1("H*")
          expanded.chars.reverse.join(".")
        end

        def next_resolver
          index = @resolver_index.increment - 1
          @resolvers[index % @resolvers.length]
        end

        def throttle(resolver)
          mutex_for(resolver).synchronize do
            interval = 1.0 / resolver_qps(resolver)
            now = @clock.call
            last = @last_query_at[resolver].to_f
            wait_time = (last + interval) - now
            if wait_time.positive?
              @sleeper.call(wait_time)
              now = @clock.call
            end
            @last_query_at[resolver] = now
          end
        end

        def resolver_qps(resolver)
          @trusted_resolvers.include?(resolver) ? DEFAULT_TRUSTED_QPS : DEFAULT_PUBLIC_QPS
        end

        def mutex_for(resolver)
          @resolver_mutexes.compute_if_absent(resolver) { Mutex.new }
        end

        def default_dns_factory(resolver)
          Resolv::DNS.new(nameserver: [resolver], search: [], ndots: 1)
        end

        def query_resolver(resolver, name, type)
          dns = @dns_factory.call(resolver)
          resources = Array(dns.getresources(name, RECORD_TYPES.fetch(type)))
          answers = resources.map { |resource| normalize_answer(type, resource) }.compact

          if answers.empty?
            { resolver: resolver, status: :no_answer, answers: [], error: "no records returned", retriable: false }
          else
            { resolver: resolver, status: :success, answers: answers, error: nil, retriable: false }
          end
        rescue Resolv::ResolvTimeout => e
          { resolver: resolver, status: :timeout, answers: [], error: e.message, retriable: true }
        rescue Resolv::ResolvError => e
          retriable = e.message.to_s.upcase.include?("SERVFAIL")
          { resolver: resolver, status: retriable ? :servfail : :error, answers: [], error: e.message, retriable: retriable }
        rescue IOError, SystemCallError => e
          { resolver: resolver, status: :error, answers: [], error: e.message, retriable: false }
        ensure
          dns&.close if dns.respond_to?(:close)
        end

        def normalize_answer(type, resource)
          ttl = resource.respond_to?(:ttl) ? resource.ttl : nil
          value = case type
                  when :a, :aaaa
                    resource.address.to_s
                  when :cname, :ns, :ptr
                    resource.name.to_s
                  when :mx
                    { exchange: resource.exchange.to_s, preference: resource.preference }
                  when :txt
                    Array(resource.data).join(" ")
                  when :srv
                    {
                      target: resource.target.to_s,
                      port: resource.port,
                      priority: resource.priority,
                      weight: resource.weight
                    }
                  when :soa
                    {
                      mname: resource.mname.to_s,
                      rname: resource.rname.to_s,
                      serial: resource.serial,
                      refresh: resource.refresh,
                      retry: resource.retry,
                      expire: resource.expire,
                      minimum: resource.minimum
                    }
                  end

          { type: type, value: value, ttl: ttl }
        rescue NoMethodError
          nil
        end

        def backoff_duration(attempt)
          0.1 * (2**attempt)
        end

        def mark_success(resolver)
          score = @reliability[resolver].to_f
          @reliability[resolver] = [(score * 0.8) + 0.2, 1.0].min
        end

        def mark_failure(resolver, retriable)
          return unless retriable

          score = @reliability[resolver].to_f
          @reliability[resolver] = [score - 0.15, 0.0].max
          log_warning("Resolver #{resolver} reliability decreased to #{@reliability[resolver].round(2)}")
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
