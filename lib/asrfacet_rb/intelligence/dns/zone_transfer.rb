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

require "resolv"
require "socket"
require "time"

module ASRFacet
  module Intelligence
    module Dns
      class ZoneTransfer
        AxfrQuery = Class.new(Resolv::DNS::Query)
        AxfrQuery.const_set(:TypeValue, 252)
        AxfrQuery.const_set(:ClassValue, 1)

        def initialize(logger: nil, timeout: 3, socket_factory: nil)
          @logger = logger
          @timeout = timeout.to_i.positive? ? timeout.to_i : 3
          @socket_factory = socket_factory || ->(host, port) { TCPSocket.new(host, port) }
        end

        def attempt(domain)
          nameservers = lookup_nameservers(domain)
          nameservers.map do |nameserver|
            attempted_at = Time.now.utc.iso8601
            log_info("AXFR attempt against #{nameserver} for #{domain}")
            records = perform_axfr(nameserver, domain)
            result = {
              domain: domain.to_s.downcase,
              nameserver: nameserver,
              attempted_at: attempted_at,
              success: records.any?,
              records: records,
              error: records.any? ? nil : "zone transfer failed"
            }
            log_info("AXFR #{result[:success] ? 'succeeded' : 'failed'} against #{nameserver} for #{domain}")
            result
          rescue StandardError => e
            log_warning("AXFR failed against #{nameserver} for #{domain}: #{e.message}")
            {
              domain: domain.to_s.downcase,
              nameserver: nameserver,
              attempted_at: attempted_at,
              success: false,
              records: [],
              error: e.message
            }
          end
        end

        private

        def lookup_nameservers(domain)
          Resolv::DNS.open do |dns|
            dns.getresources(domain.to_s, Resolv::DNS::Resource::IN::NS).map { |resource| resource.name.to_s }.uniq
          end
        rescue StandardError
          []
        end

        def perform_axfr(nameserver, domain)
          query = build_axfr_query(domain)
          socket = @socket_factory.call(nameserver, 53)
          socket.write([query.bytesize].pack("n") + query)

          records = []
          soa_count = 0
          loop do
            message = read_message(socket)
            break if message.nil?

            decoded = Resolv::DNS::Message.decode(message)
            Array(decoded.answer).each do |name, ttl, resource|
              records << record_to_hash(name, ttl, resource)
              soa_count += 1 if resource.is_a?(Resolv::DNS::Resource::IN::SOA)
            end
            break if soa_count >= 2
          end

          records.compact
        ensure
          socket&.close
        end

        def build_axfr_query(domain)
          message = Resolv::DNS::Message.new
          message.rd = 0
          message.add_question(domain.to_s, AxfrQuery)
          message.encode
        end

        def read_message(socket)
          header = socket.read(2)
          return nil if header.nil? || header.bytesize < 2

          length = header.unpack1("n")
          socket.read(length)
        end

        def record_to_hash(name, ttl, resource)
          {
            name: name.to_s,
            ttl: ttl,
            type: resource.class.name.split("::").last,
            data: normalize_resource(resource)
          }
        end

        def normalize_resource(resource)
          if resource.respond_to?(:address)
            resource.address.to_s
          elsif resource.respond_to?(:name)
            resource.name.to_s
          elsif resource.respond_to?(:exchange)
            { exchange: resource.exchange.to_s, preference: resource.preference }
          elsif resource.respond_to?(:target)
            {
              target: resource.target.to_s,
              port: resource.port,
              priority: resource.priority,
              weight: resource.weight
            }
          elsif resource.respond_to?(:mname)
            {
              mname: resource.mname.to_s,
              rname: resource.rname.to_s,
              serial: resource.serial,
              refresh: resource.refresh,
              retry: resource.retry,
              expire: resource.expire,
              minimum: resource.minimum
            }
          elsif resource.respond_to?(:data)
            Array(resource.data).join(" ")
          else
            resource.to_s
          end
        end

        def log_info(message)
          if @logger&.respond_to?(:info)
            @logger.info(message)
          elsif @logger&.respond_to?(:print_status)
            @logger.print_status(message)
          end
        rescue StandardError
          nil
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
