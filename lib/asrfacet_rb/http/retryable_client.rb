# Part of ASRFacet-Rb — authorized testing only
require "net/http"
require "openssl"
require "uri"

module ASRFacet
  module HTTP
    class RetryableClient
      DEFAULT_OPTS = {
        max_retries: 3,
        open_timeout: 5,
        read_timeout: 10,
        follow_redirects: true,
        max_redirects: 5,
        verify_ssl: false,
        user_agent: "ASRFacet-Rb/#{ASRFacet::VERSION}"
      }.freeze

      RETRY_ERRORS = [
        Net::OpenTimeout,
        Net::ReadTimeout,
        Errno::ECONNREFUSED,
        Errno::ECONNRESET,
        Errno::EHOSTUNREACH,
        SocketError,
        IOError
      ].freeze

      def initialize(options = {})
        @options = DEFAULT_OPTS.merge(symbolize_keys(options))
      rescue StandardError
        @options = DEFAULT_OPTS.dup
      end

      def get(url, headers: {}, timeout: nil, opts: {})
        request(:get, url, headers: headers, timeout: timeout, opts: opts)
      rescue StandardError
        nil
      end

      def head(url, headers: {}, timeout: nil, opts: {})
        request(:head, url, headers: headers, timeout: timeout, opts: opts)
      rescue StandardError
        nil
      end

      private

      def request(method, url, headers:, timeout:, opts:, redirects_left: nil, attempt: 0)
        merged_opts = @options.merge(symbolize_keys(opts))
        redirects_left ||= merged_opts[:max_redirects].to_i
        uri = URI.parse(url.to_s)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == "https"
        http.open_timeout = timeout || merged_opts[:open_timeout]
        http.read_timeout = timeout || merged_opts[:read_timeout]
        http.verify_mode = merged_opts[:verify_ssl] ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE

        request_class = method == :head ? Net::HTTP::Head : Net::HTTP::Get
        request = request_class.new(uri.request_uri)
        { "User-Agent" => merged_opts[:user_agent] }.merge(headers || {}).each do |key, value|
          request[key] = value
        end

        response = http.request(request)
        if response.is_a?(Net::HTTPRedirection) && merged_opts[:follow_redirects] && redirects_left.positive?
          location = response["location"].to_s
          return nil if location.empty?

          return request(
            method,
            URI.join(url.to_s, location).to_s,
            headers: headers,
            timeout: timeout,
            opts: merged_opts,
            redirects_left: redirects_left - 1,
            attempt: attempt
          )
        end

        response
      rescue *RETRY_ERRORS
        return nil if attempt >= merged_opts[:max_retries].to_i

        sleep((2**attempt) * 0.1)
        request(
          method,
          url,
          headers: headers,
          timeout: timeout,
          opts: merged_opts,
          redirects_left: redirects_left,
          attempt: attempt + 1
        )
      rescue StandardError
        nil
      end

      def symbolize_keys(hash)
        hash.each_with_object({}) do |(key, value), memo|
          memo[key.to_sym] = value
        end
      rescue StandardError
        {}
      end
    end
  end
end
