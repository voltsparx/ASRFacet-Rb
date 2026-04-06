# Part of ASRFacet-Rb — authorized testing only
require "resolv"
require "socket"

module ASRFacet::Engines
  class DnsEngine
    def run(domain)
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

    def attempt_zone_transfer(domain)
      nameservers = run(domain).fetch(:ns, [])
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

    def fetch_records(dns, domain, klass)
      dns.getresources(domain.to_s, klass).map do |record|
        yield(record)
      end
    rescue StandardError
      []
    end
  end
end
