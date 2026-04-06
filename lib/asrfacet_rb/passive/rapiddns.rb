# Part of ASRFacet-Rb — authorized testing only
require "nokogiri"

module ASRFacet::Passive
  class RapidDNS < BaseSource
    def name
      "rapiddns"
    end

    def run(domain, _api_keys = {})
      body = fetch("https://rapiddns.io/subdomain/#{domain}?full=1")
      return [] if body.to_s.strip.empty?

      doc = Nokogiri::HTML(body)
      pattern = /(?:\A|\s)([a-z0-9][a-z0-9\-_\.]*\.#{Regexp.escape(domain)})(?:\s|\z)/i

      doc.css("td").each_with_object(Set.new) do |cell, memo|
        text = cell.text.to_s.strip.downcase
        match = text.match(pattern)
        memo << match[1] if match
      end.to_a.sort
    rescue StandardError
      []
    end
  end
end
