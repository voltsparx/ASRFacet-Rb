# Part of ASRFacet-Rb — authorized testing only
require "nokogiri"
require "set"
require "uri"

module ASRFacet
  module Engines
    class JsEndpointEngine
      JS_PATTERNS = [
        /['"]\/api\/[a-zA-Z0-9_\-\/]+['"]/,
        /['"]\/v[0-9]+\/[a-zA-Z0-9_\-\/]+['"]/,
        /fetch\(['"]([^'"]+)['"]/,
        /axios\.\w+\(['"]([^'"]+)['"]/,
        /XMLHttpRequest/,
        /api[_-]?key\s*[:=]\s*['"][^'"]{8,}['"]/i,
        /token\s*[:=]\s*['"][^'"]{16,}['"]/i,
        /secret\s*[:=]\s*['"][^'"]{8,}['"]/i
      ].freeze

      def initialize(client: ASRFacet::HTTP::RetryableClient.new)
        @client = client
      end

      def run(base_url, js_urls)
        endpoint_matches = Set.new
        findings = []
        secret_count = 0

        Array(js_urls).uniq.each do |js_url|
          response = @client.get(js_url)
          next if response.nil?

          content = response.body.to_s
          JS_PATTERNS.each do |pattern|
            content.to_enum(:scan, pattern).each do
              match = Regexp.last_match
              extracted = match[1] || match[0]
              if secret_pattern?(pattern)
                secret_count += 1
                findings << secret_finding(base_url, js_url)
              else
                endpoint_matches << normalize_match(extracted)
              end
            rescue StandardError
              nil
            end
          end
        rescue StandardError
          nil
        end

        {
          js_files_scanned: Array(js_urls).uniq.count,
          endpoints_found: endpoint_matches.to_a.reject(&:empty?).sort,
          potential_secrets: secret_count,
          findings: findings.uniq { |finding| [finding[:host], finding[:title], finding[:description]] }
        }
      rescue StandardError
        { js_files_scanned: 0, endpoints_found: [], potential_secrets: 0, findings: [] }
      end

      def extract_js_urls(html_body, base_url)
        doc = Nokogiri::HTML(html_body.to_s)
        doc.css("script[src]").filter_map do |script|
          src = script["src"].to_s.strip
          next if src.empty?
          next unless src.match?(/\.js(?:$|\?)/i)

          URI.join(base_url.to_s, src).to_s
        rescue StandardError
          nil
        end.uniq.sort
      rescue StandardError
        []
      end

      private

      def normalize_match(match)
        match.to_s.gsub(/\A['"]|['"]\z/, "")
      rescue StandardError
        ""
      end

      def secret_pattern?(pattern)
        source = pattern.source.to_s
        source.include?("api[_-]?key") || source.include?("token") || source.include?("secret")
      rescue StandardError
        false
      end

      def secret_finding(base_url, js_url)
        host = URI.parse(base_url.to_s).host.to_s
        {
          title: "Potential Secret Pattern in JavaScript",
          severity: ASRFacet::Core::Severity::MEDIUM,
          host: host,
          description: "A JavaScript file exposed a pattern consistent with an API key, token, or secret placeholder.",
          remediation: "Review #{js_url} and move secrets to server-side storage or rotate them if real values were exposed."
        }
      rescue StandardError
        {
          title: "Potential Secret Pattern in JavaScript",
          severity: ASRFacet::Core::Severity::MEDIUM,
          host: base_url.to_s,
          description: "A JavaScript file exposed a potential secret pattern.",
          remediation: "Review the affected JavaScript asset and rotate any exposed credentials."
        }
      end
    end
  end
end
