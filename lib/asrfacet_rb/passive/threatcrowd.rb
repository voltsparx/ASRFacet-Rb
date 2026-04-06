# Part of ASRFacet-Rb — authorized testing only
require "json"

module ASRFacet::Passive
  class ThreatCrowd < BaseSource
    def name
      "threatcrowd"
    end

    def run(domain, _api_keys = {})
      body = fetch("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=#{domain}")
      return [] if body.to_s.strip.empty?

      Array(JSON.parse(body)["subdomains"]).map(&:to_s).map(&:downcase).select do |hostname|
        hostname == domain || hostname.end_with?(".#{domain}")
      end.uniq.sort
    rescue StandardError
      []
    end
  end
end
