# Part of ASRFacet-Rb — authorized testing only
require "resolv"

module ASRFacet::Core
  class Target
    attr_reader :domain, :ip

    def initialize(input)
      normalized = input.to_s.strip.downcase.sub(%r{\Ahttps?://}, "").sub(%r{/+\z}, "")
      @domain = normalized
      @ip = Resolv.getaddress(@domain)
      @cache = {}
      @client = ASRFacet::HTTP::RetryableClient.new
    rescue StandardError
      @domain = input.to_s.strip.downcase.sub(%r{\Ahttps?://}, "").sub(%r{/+\z}, "")
      @ip = nil
      @cache = {}
      @client = ASRFacet::HTTP::RetryableClient.new
    end

    def url(path = "")
      clean_path = path.to_s.strip
      clean_path = clean_path.sub(%r{\A/+}, "")
      return "https://#{@domain}" if clean_path.empty?

      "https://#{@domain}/#{clean_path}".gsub(%r{(?<!:)//+}, "/")
    rescue StandardError
      "https://#{@domain}"
    end

    def get(path, headers: {})
      cache_key = [path.to_s, headers.to_a.sort].hash
      return @cache[cache_key] if @cache.key?(cache_key)

      @cache[cache_key] = @client.get(url(path), headers: headers)
    rescue StandardError
      nil
    end

    def homepage
      @homepage ||= get("")
    rescue StandardError
      nil
    end

    def alive?
      !homepage.nil?
    rescue StandardError
      false
    end

    def redirects_to_https?
      client = ASRFacet::HTTP::RetryableClient.new(follow_redirects: false)
      response = client.get("http://#{@domain}")
      response && response.code.to_i.between?(300, 399) && response["location"].to_s.start_with?("https://")
    rescue StandardError
      false
    end
  end
end
