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
        user_agent: "ASRFacet-Rb/#{ASRFacet::VERSION}",
        rate_controller: nil
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
        @rate_controller = @options[:rate_controller]
      rescue StandardError
        @options = DEFAULT_OPTS.dup
        @rate_controller = nil
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

      def post(url, body: nil, headers: {}, timeout: nil, opts: {})
        request(:post, url, headers: headers, body: body, timeout: timeout, opts: opts)
      rescue StandardError
        nil
      end

      private

      def request(method, url, headers:, body: nil, timeout:, opts:, redirects_left: nil, attempt: 0, rate_limit_attempt: 0)
        merged_opts = @options.merge(symbolize_keys(opts))
        redirects_left = merged_opts[:max_redirects].to_i if redirects_left.nil?
        uri = URI.parse(url.to_s)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == "https"
        http.open_timeout = timeout || merged_opts[:open_timeout]
        http.read_timeout = timeout || merged_opts[:read_timeout]
        http.verify_mode = merged_opts[:verify_ssl] ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE

        request = build_request(method, uri, headers, body, merged_opts[:user_agent])
        response = http.request(request)
        observe_rate(response)

        if response.code.to_i == 429 && rate_limit_attempt < merged_opts[:max_retries].to_i
          ASRFacet::Core::ThreadSafe.print_warning("429 received from #{uri.host} — waiting #{current_delay(merged_opts[:rate_controller])}ms")
          wait_for_rate_control(merged_opts[:rate_controller])
          return request(
            method,
            url,
            headers: headers,
            body: body,
            timeout: timeout,
            opts: merged_opts,
            redirects_left: redirects_left,
            attempt: attempt,
            rate_limit_attempt: rate_limit_attempt + 1
          )
        end

        if response.is_a?(Net::HTTPRedirection) && merged_opts[:follow_redirects] && redirects_left.to_i.positive?
          location = response["location"].to_s
          return response if location.empty?

          return request(
            method,
            URI.join(url.to_s, location).to_s,
            headers: headers,
            body: body,
            timeout: timeout,
            opts: merged_opts,
            redirects_left: redirects_left.to_i - 1,
            attempt: attempt,
            rate_limit_attempt: rate_limit_attempt
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
          body: body,
          timeout: timeout,
          opts: merged_opts,
          redirects_left: redirects_left,
          attempt: attempt + 1,
          rate_limit_attempt: rate_limit_attempt
        )
      rescue StandardError
        nil
      end

      def build_request(method, uri, headers, body, user_agent)
        request_class = case method.to_sym
                        when :head then Net::HTTP::Head
                        when :post then Net::HTTP::Post
                        else Net::HTTP::Get
                        end
        request = request_class.new(uri.request_uri)
        { "User-Agent" => user_agent }.merge(headers || {}).each do |key, value|
          request[key] = value
        end
        request.body = body unless body.nil?
        request
      rescue StandardError
        Net::HTTP::Get.new(uri.request_uri)
      end

      def observe_rate(response)
        controller = @rate_controller || @options[:rate_controller]
        return nil if response.nil? || controller.nil?

        controller.observe(response.code.to_i)
        controller.wait
      rescue StandardError
        nil
      end

      def wait_for_rate_control(controller)
        controller&.wait
      rescue StandardError
        nil
      end

      def current_delay(controller)
        controller&.current_delay.to_i
      rescue StandardError
        0
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
