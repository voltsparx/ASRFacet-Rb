# Part of ASRFacet-Rb — authorized testing only
require "json"

module ASRFacet::Passive
  class BufferOver < BaseSource
    def name
      "bufferover"
    end

    def run(domain, _api_keys = {})
      body = fetch("https://dns.bufferover.run/dns?q=.#{domain}")
      return [] if body.to_s.strip.empty?

      json = JSON.parse(body)
      records = Array(json["FDNS_A"]) + Array(json["RDNS"])
      records.each_with_object(Set.new) do |record, memo|
        hostname = record.to_s.split(",").last.to_s.strip.downcase.sub(/\A\*\./, "")
        memo << hostname if hostname == domain || hostname.end_with?(".#{domain}")
      end.to_a.sort
    rescue StandardError
      []
    end
  end
end
