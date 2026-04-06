# Part of ASRFacet-Rb — authorized testing only
require "json"

module ASRFacet::Passive
  class AlienVault < BaseSource
    def name
      "alienvault"
    end

    def run(domain, _api_keys = {})
      body = fetch("https://otx.alienvault.com/api/v1/indicators/domain/#{domain}/passive_dns")
      return [] if body.to_s.strip.empty?

      JSON.parse(body).fetch("passive_dns", []).each_with_object(Set.new) do |entry, memo|
        hostname = entry.fetch("hostname", "").to_s.strip.downcase
        memo << hostname if hostname == domain || hostname.end_with?(".#{domain}")
      end.to_a.sort
    rescue StandardError
      []
    end
  end
end
