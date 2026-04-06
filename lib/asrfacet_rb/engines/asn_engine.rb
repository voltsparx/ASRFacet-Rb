# Part of ASRFacet-Rb — authorized testing only
require "json"

module ASRFacet::Engines
  class AsnEngine
    def initialize(client: ASRFacet::HTTP::RetryableClient.new)
      @client = client
    end

    def run(ip)
      response = @client.get("http://ip-api.com/json/#{ip}?fields=as,org,isp,country,regionName,city")
      return {} if response.nil?

      json = JSON.parse(response.body.to_s)
      {
        asn: json["as"],
        org: json["org"],
        isp: json["isp"],
        country: json["country"],
        region: json["regionName"],
        city: json["city"]
      }
    rescue StandardError
      {}
    end
  end
end
