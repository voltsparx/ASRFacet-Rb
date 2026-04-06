# Part of ASRFacet-Rb — authorized testing only
require "json"

module ASRFacet::Passive
  class Shodan < BaseSource
    def name
      "shodan"
    end

    def run(domain, api_keys = {})
      api_key = api_keys[:shodan].to_s.strip
      return [] if api_key.empty?

      body = fetch("https://api.shodan.io/dns/domain/#{domain}?key=#{api_key}")
      return [] if body.to_s.strip.empty?

      JSON.parse(body).fetch("subdomains", []).each_with_object(Set.new) do |subdomain, memo|
        hostname = "#{subdomain}.#{domain}".downcase
        memo << hostname
      end.to_a.sort
    rescue StandardError
      []
    end
  end
end
