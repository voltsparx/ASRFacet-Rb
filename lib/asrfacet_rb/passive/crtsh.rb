# Part of ASRFacet-Rb — authorized testing only
require "json"

module ASRFacet::Passive
  class CrtSh < BaseSource
    def name
      "crt.sh"
    end

    def run(domain, _api_keys = {})
      body = fetch("https://crt.sh/?q=%25.#{domain}&output=json")
      return [] if body.to_s.strip.empty?

      JSON.parse(body).each_with_object(Set.new) do |entry, memo|
        entry.fetch("name_value", "").to_s.split("\n").each do |hostname|
          clean = hostname.strip.downcase.sub(/\A\*\./, "")
          memo << clean if clean == domain || clean.end_with?(".#{domain}")
        end
      end.to_a.sort
    rescue StandardError
      []
    end
  end
end
