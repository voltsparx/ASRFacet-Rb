# Part of ASRFacet-Rb — authorized testing only
require "net/http"
require "openssl"
require "uri"

module ASRFacet::Passive
  class BaseSource
    def name
      raise NotImplementedError, "Subclasses must implement #name"
    end

    def run(_domain, _api_keys = {})
      raise NotImplementedError, "Subclasses must implement #run"
    end

    protected

    def fetch(url, headers: {}, timeout: 10)
      uri = URI.parse(url.to_s)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == "https"
      http.open_timeout = timeout
      http.read_timeout = timeout
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE

      request = Net::HTTP::Get.new(uri.request_uri)
      headers.each { |key, value| request[key] = value }

      response = http.request(request)
      response.body
    rescue StandardError
      nil
    end
  end
end
