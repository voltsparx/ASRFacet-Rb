# Part of ASRFacet-Rb — authorized testing only
module ASRFacet
  module Engines
    class AssetScorer
      SCORE_RULES = [
        { label: "Admin panel found", condition: ->(asset) { Array(asset[:paths]).any? { |path| path[:path].to_s.match?(/admin/i) && path[:status].to_i == 200 } }, score: 25 },
        { label: "Exposed .git directory", condition: ->(asset) { Array(asset[:paths]).any? { |path| path[:path].to_s == "/.git/HEAD" && path[:status].to_i == 200 } }, score: 30 },
        { label: "Exposed .env file", condition: ->(asset) { Array(asset[:paths]).any? { |path| path[:path].to_s == "/.env" && path[:status].to_i == 200 } }, score: 35 },
        { label: "Missing HSTS", condition: ->(asset) { asset.dig(:security_headers, "Strict-Transport-Security").nil? || asset.dig(:security_headers, "Strict-Transport-Security") == false }, score: 10 },
        { label: "Missing CSP", condition: ->(asset) { asset.dig(:security_headers, "Content-Security-Policy").nil? || asset.dig(:security_headers, "Content-Security-Policy") == false }, score: 10 },
        { label: "Expired certificate", condition: ->(asset) { asset.dig(:cert, :expired) == true }, score: 20 },
        { label: "Open non-standard port", condition: ->(asset) { Array(asset[:ports]).any? { |port| ![80, 443, 8080, 8443].include?(port[:port].to_i) } }, score: 15 },
        { label: "Development subdomain", condition: ->(asset) { asset[:host].to_s.match?(/dev|staging|test|beta|internal/i) }, score: 20 },
        { label: "API endpoint detected", condition: ->(asset) { Array(asset[:technologies]).include?("Express") || asset[:host].to_s.match?(/api/i) }, score: 15 },
        { label: "No CDN (direct IP)", condition: ->(asset) { asset[:cdn].nil? || asset[:cdn].to_s.empty? }, score: 5 }
      ].freeze

      def score(asset_hash)
        asset = symbolize_keys(asset_hash)
        matched_rules = SCORE_RULES.select { |rule| safe_match?(rule[:condition], asset) }
        {
          host: asset[:host].to_s,
          total_score: matched_rules.sum { |rule| rule[:score].to_i },
          matched_rules: matched_rules.map { |rule| rule[:label] }
        }
      rescue StandardError
        { host: asset_hash.to_s, total_score: 0, matched_rules: [] }
      end

      def score_all(result_store)
        normalize_http_assets(result_store).map { |asset| score(asset) }
                                         .sort_by { |entry| [-entry[:total_score].to_i, entry[:host].to_s] }
      rescue StandardError
        []
      end

      def top(result_store, n: 10)
        score_all(result_store).first(n.to_i.positive? ? n.to_i : 10)
      rescue StandardError
        []
      end

      private

      def normalize_http_assets(result_store)
        store_hash = result_store.respond_to?(:to_h) && !result_store.is_a?(Hash) ? result_store.to_h : symbolize_keys(result_store)
        certs_by_host = Array(store_hash[:certs]).each_with_object({}) do |cert, memo|
          entry = symbolize_keys(cert)
          memo[entry[:host].to_s] = entry
        end
        ports_by_host = Array(store_hash[:open_ports]).group_by { |port| symbolize_keys(port)[:host].to_s }

        Array(store_hash[:http_responses]).map do |response|
          entry = symbolize_keys(response)
          entry[:paths] = Array(entry[:interesting_paths]).map { |path| symbolize_keys(path) }
          entry[:ports] = Array(ports_by_host[entry[:host].to_s]).map { |port| symbolize_keys(port) }
          entry[:cert] = certs_by_host[entry[:host].to_s]
          entry
        end
      rescue StandardError
        []
      end

      def safe_match?(condition, asset)
        condition.call(asset)
      rescue StandardError
        false
      end

      def symbolize_keys(value)
        case value
        when Hash
          value.each_with_object({}) do |(key, nested), memo|
            memo[key.to_sym] = symbolize_keys(nested)
          end
        when Array
          value.map { |entry| symbolize_keys(entry) }
        else
          value
        end
      rescue StandardError
        {}
      end
    end
  end
end
