# Part of ASRFacet-Rb — authorized testing only
require "json"
require "time"

module ASRFacet
  module Engines
    class AsnEngine
      def initialize(target = nil, options = {}, client: ASRFacet::HTTP::RetryableClient.new)
        @target = target
        @options = options || {}
        @client = client
      end

      def run(ip = @target)
        response = @client.get("http://ip-api.com/json/#{ip}?fields=as,org,isp,country,regionName,city")
        data = if response.nil?
                 {}
               else
                 json = JSON.parse(response.body.to_s)
                 {
                   asn: json["as"],
                   org: json["org"],
                   isp: json["isp"],
                   country: json["country"],
                   region: json["regionName"],
                   city: json["city"]
                 }
               end

        {
          engine: "asn_engine",
          target: ip.to_s,
          timestamp: Time.now.iso8601,
          status: data.empty? ? :failed : :success,
          data: data,
          errors: []
        }
      rescue StandardError => e
        { engine: "asn_engine", target: ip.to_s, timestamp: Time.now.iso8601, status: :failed, data: {}, errors: [e.message] }
      end
    end
  end
end
