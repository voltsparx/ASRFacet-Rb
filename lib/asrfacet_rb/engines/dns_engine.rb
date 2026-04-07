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
  module Engines
    class DnsEngine
      include ASRFacet::Mixins::Network

      RECORD_TYPES = {
        a: Resolv::DNS::Resource::IN::A,
        aaaa: Resolv::DNS::Resource::IN::AAAA,
        mx: Resolv::DNS::Resource::IN::MX,
        ns: Resolv::DNS::Resource::IN::NS,
        txt: Resolv::DNS::Resource::IN::TXT,
        cname: Resolv::DNS::Resource::IN::CNAME,
        soa: Resolv::DNS::Resource::IN::SOA
      }.freeze

      def initialize(target = nil, options = {})
        @target = target
        @options = options || {}
      end

      def run(domain = @target)
        target = domain.to_s
        records = lookup_records(target)
        wildcard_ips = dns_lookup("wildcard-#{rand(100_000)}.#{target}")
        status = records.values.flatten.empty? ? :failed : :success
        {
          engine: "dns_engine",
          target: target,
          timestamp: Time.now.iso8601,
          status: status,
          data: records.merge(wildcard: !wildcard_ips.empty?, wildcard_ips: wildcard_ips, zone_transfer: attempt_zone_transfer(target)),
          errors: status == :failed ? ["No DNS records found"] : []
        }
      rescue StandardError => e
        {
          engine: "dns_engine",
          target: domain.to_s,
          timestamp: Time.now.iso8601,
          status: :failed,
          data: empty_data,
          errors: [e.message]
        }
      end

      def attempt_zone_transfer(domain)
        Array(lookup_records(domain)[:ns]).each do |nameserver|
          socket = TCPSocket.new(nameserver.to_s, 53)
          socket.write(" ")
        rescue StandardError
          next
        ensure
          socket&.close rescue nil
        end
        []
      rescue StandardError
        []
      end

      private

      def lookup_records(domain)
        RECORD_TYPES.each_with_object({}) do |(type, klass), memo|
          memo[type] = fetch_records(domain, klass)
        end
      rescue StandardError
        empty_data.reject { |key, _value| %i[wildcard wildcard_ips zone_transfer].include?(key) }
      end

      def fetch_records(domain, klass)
        Resolv::DNS.open do |dns|
          dns.getresources(domain.to_s, klass).map { |record| normalize_record(record) }.compact.uniq
        end
      rescue StandardError
        []
      end

      def normalize_record(record)
        if record.respond_to?(:address)
          record.address.to_s
        elsif record.respond_to?(:exchange)
          record.exchange.to_s
        elsif record.respond_to?(:name)
          record.name.to_s
        elsif record.respond_to?(:data)
          Array(record.data).join(" ")
        elsif record.respond_to?(:mname) && record.respond_to?(:rname)
          {
            mname: record.mname.to_s,
            rname: record.rname.to_s,
            serial: record.serial,
            refresh: record.refresh,
            retry: record.retry,
            expire: record.expire,
            minimum: record.minimum
          }
        else
          record.to_s
        end
      rescue StandardError
        nil
      end

      def empty_data
        {
          a: [],
          aaaa: [],
          mx: [],
          ns: [],
          txt: [],
          cname: [],
          soa: [],
          wildcard: false,
          wildcard_ips: [],
          zone_transfer: []
        }
      rescue StandardError
        {}
      end
    end
  end
end
