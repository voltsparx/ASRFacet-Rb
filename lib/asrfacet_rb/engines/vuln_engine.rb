# Part of ASRFacet-Rb — authorized testing only
require "resolv"
require "uri"

module ASRFacet::Engines
  class VulnEngine
    include ASRFacet::Core::FindingBuilder

    TAKEOVER_SIGNATURES = {
      "AWS" => { cname: /amazonaws\.com/i, body: /no such bucket|not found/i },
      "GitHub" => { cname: /github\.io/i, body: /there isn't a github pages site here/i },
      "Heroku" => { cname: /herokudns\.com|herokuapp\.com/i, body: /no such app/i },
      "Netlify" => { cname: /netlify\.com|netlify\.app/i, body: /not found/i },
      "Shopify" => { cname: /shops\.myshopify\.com/i, body: /sorry, this shop is currently unavailable/i },
      "Zendesk" => { cname: /zendesk\.com/i, body: /help center closed|not found/i },
      "ReadMe" => { cname: /readme\.io/i, body: /project doesn't exist/i },
      "Fastly" => { cname: /fastly\.net/i, body: /fastly error|unknown domain/i }
    }.freeze

    def initialize(target, http_results: [], cert_results: [])
      @target = target
      @http_results = Array(http_results)
      @cert_results = Array(cert_results)
      @client = ASRFacet::HTTP::RetryableClient.new(follow_redirects: false)
    end

    def run
      findings = []
      findings.concat(check_exposed_git)
      findings.concat(check_exposed_env)
      findings.concat(check_subdomain_takeover)
      findings.concat(check_security_headers)
      findings.concat(check_expired_cert)
      findings.concat(check_cors_misconfiguration)
      findings.concat(check_directory_listing)
      findings.compact
    rescue StandardError
      []
    end

    def check_exposed_git
      @http_results.filter_map do |result|
        next unless path_status(result, "/.git/HEAD") == 200

        exposed_git(result[:host])
      rescue StandardError
        nil
      end
    rescue StandardError
      []
    end

    def check_exposed_env
      @http_results.filter_map do |result|
        next unless path_status(result, "/.env") == 200

        exposed_env(result[:host])
      rescue StandardError
        nil
      end
    rescue StandardError
      []
    end

    def check_subdomain_takeover
      @http_results.filter_map do |result|
        host = result[:host]
        cname = resolve_cname(host)
        next if cname.to_s.empty?

        provider_name, signature = TAKEOVER_SIGNATURES.find { |_name, value| cname.match?(value[:cname]) }
        next unless provider_name

        response = @client.get(result[:url].to_s.empty? ? "https://#{host}" : result[:url])
        body = response&.body.to_s
        next unless response.nil? || body.match?(signature[:body]) || body.match?(/not found/i)

        subdomain_takeover(host, cname, provider_name)
      rescue StandardError
        nil
      end
    rescue StandardError
      []
    end

    def check_security_headers
      @http_results.flat_map do |result|
        headers = result[:security_headers] || {}
        findings = []
        findings << missing_security_header(result[:host], "Strict-Transport-Security") if headers["Strict-Transport-Security"].to_s.empty?
        findings << missing_security_header(result[:host], "Content-Security-Policy") if headers["Content-Security-Policy"].to_s.empty?
        findings
      rescue StandardError
        []
      end
    rescue StandardError
      []
    end

    def check_expired_cert
      @cert_results.filter_map do |cert|
        next unless cert[:expired]

        expired_cert(cert[:host], cert[:not_after])
      rescue StandardError
        nil
      end
    rescue StandardError
      []
    end

    def check_cors_misconfiguration
      @http_results.filter_map do |result|
        response = @client.get(result[:url], headers: { "Origin" => "https://evil.com" })
        next if response.nil?

        acao = response["Access-Control-Allow-Origin"].to_s
        acac = response["Access-Control-Allow-Credentials"].to_s.downcase
        next unless ["https://evil.com", "*"].include?(acao) && acac == "true"

        cors_misconfiguration(result[:host])
      rescue StandardError
        nil
      end
    rescue StandardError
      []
    end

    def check_directory_listing
      @http_results.filter_map do |result|
        next unless result[:body_preview].to_s.match?(/index of/i)

        path = URI.parse(result[:url]).path.to_s
        directory_listing(result[:host], path.empty? ? "/" : path)
      rescue StandardError
        nil
      end
    rescue StandardError
      []
    end

    private

    def path_status(result, target_path)
      Array(result[:interesting_paths]).find { |entry| entry[:path] == target_path }&.dig(:status)
    rescue StandardError
      nil
    end

    def resolve_cname(host)
      Resolv::DNS.open do |dns|
        record = dns.getresources(host, Resolv::DNS::Resource::IN::CNAME).first
        record&.name.to_s
      end
    rescue StandardError
      nil
    end
  end
end
