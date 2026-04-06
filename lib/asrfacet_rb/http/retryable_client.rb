# Part of ASRFacet-Rb — authorized testing only
require "net/http"
require "openssl"
require "uri"

module ASRFacet::HTTP
  class RetryableClient
    DEFAULT_OPTS = {
      max_retries: 3,
      open_timeout: 5,
      read_timeout: 10,
      follow_redirects: true,
      max_redirects: 5,
      verify_ssl: false,
      user_agent: "ASRFacet-Rb/0.1.0"
    }.freeze

    def initialize(options = {})
      @options = DEFAULT_OPTS.merge(options.transform_keys(&:to_sym))
    rescue StandardError
      @options = DEFAULT_OPTS.dup
    end

    def get(url, headers: {}, timeout: nil)
      request(:get, url, headers: headers, timeout: timeout)
    rescue StandardError
      nil
    end

    def head(url, headers: {})
      request(:head, url, headers: headers)
    rescue StandardError
      nil
    end

    private

    def request(method, url, headers:, timeout:, redirects_left: @options[:max_redirects], attempt: 0)
      uri = URI.parse(url.to_s)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == "https"
      http.open_timeout = timeout || @options[:open_timeout]
      http.read_timeout = timeout || @options[:read_timeout]
      http.verify_mode = @options[:verify_ssl] ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE

      request_class = method == :head ? Net::HTTP::Head : Net::HTTP::Get
      request = request_class.new(uri.request_uri)
      merged_headers = { "User-Agent" => @options[:user_agent] }.merge(headers || {})
      merged_headers.each { |key, value| request[key] = value }

      response = http.request(request)
      if redirect?(response) && @options[:follow_redirects] && redirects_left.to_i.positive?
        location = response["location"]
        return nil if location.to_s.strip.empty?

        redirected_url = URI.join(url.to_s, location).to_s
        return request(method, redirected_url, headers: headers, timeout: timeout, redirects_left: redirects_left - 1, attempt: attempt)
      end

      response
    rescue StandardError
      return nil if attempt >= @options[:max_retries].to_i

      sleep((2**attempt) * 0.1)
      request(method, url, headers: headers, timeout: timeout, redirects_left: redirects_left, attempt: attempt + 1)
    end

    def redirect?(response)
      response.is_a?(Net::HTTPRedirection)
    rescue StandardError
      false
    end
  end
end
