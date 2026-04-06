# Part of ASRFacet-Rb — authorized testing only
require "resolv"
require "socket"
require "time"

module ASRFacet
  module Engines
    class DnsEngine
      include ASRFacet::Mixins::Network

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
          data: { a: [], aaaa: [], mx: [], ns: [], txt: [], cname: [], soa: [], wildcard: false, wildcard_ips: [], zone_transfer: [] },
          errors: [e.message]
        }
      end

      def attempt_zone_transfer(domain)
        nameservers = lookup_records(domain)[:ns]
        nameservers.each do |nameserver|
          socket = TCPSocket.new(nameserver, 53)
          socket.close
        rescue StandardError
          next
        end
        []
      rescue StandardError
        []
      end

      private

      def lookup_records(domain)
        dns = Resolv::DNS.new
        {
          a: fetch_records(dns, domain, Resolv::DNS::Resource::IN::A) { |record| record.address.to_s },
          aaaa: fetch_records(dns, domain, Resolv::DNS::Resource::IN::AAAA) { |record| record.address.to_s },
          mx: fetch_records(dns, domain, Resolv::DNS::Resource::IN::MX) { |record| record.exchange.to_s },
          ns: fetch_records(dns, domain, Resolv::DNS::Resource::IN::NS) { |record| record.name.to_s },
          txt: fetch_records(dns, domain, Resolv::DNS::Resource::IN::TXT) { |record| record.data.to_s },
          cname: fetch_records(dns, domain, Resolv::DNS::Resource::IN::CNAME) { |record| record.name.to_s },
          soa: fetch_records(dns, domain, Resolv::DNS::Resource::IN::SOA) do |record|
            {
              mname: record.mname.to_s,
              rname: record.rname.to_s,
              serial: record.serial,
              refresh: record.refresh,
              retry: record.retry,
              expire: record.expire,
              minimum: record.minimum
            }
          end
        }
      rescue StandardError
        { a: [], aaaa: [], mx: [], ns: [], txt: [], cname: [], soa: [] }
      ensure
        dns&.close rescue nil
      end

      def fetch_records(dns, domain, klass)
        dns.getresources(domain.to_s, klass).map { |record| yield(record) }
      rescue StandardError
        []
      end
    end
  end
end
