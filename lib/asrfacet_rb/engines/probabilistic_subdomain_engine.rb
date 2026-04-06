# Part of ASRFacet-Rb — authorized testing only
require "set"

module ASRFacet
  module Engines
    class ProbabilisticSubdomainEngine
      REGION_HINTS = %w[us-east us-west eu-west eu-central ap-south ap-southeast].freeze
      ENV_HINTS = %w[dev prod staging test qa beta internal].freeze

      def initialize(domain, known_subdomains)
        @domain = domain.to_s.downcase
        @known = Array(known_subdomains).map(&:to_s).uniq
        @patterns = extract_patterns(@known)
      rescue StandardError
        @domain = domain.to_s.downcase
        @known = []
        @patterns = {}
      end

      def extract_patterns(subdomains)
        prefixes = Hash.new(0)
        numbered = Hash.new { |hash, key| hash[key] = [] }
        environments = Hash.new { |hash, key| hash[key] = Set.new }
        regions = Hash.new { |hash, key| hash[key] = Set.new }

        Array(subdomains).each do |subdomain|
          label = extract_label(subdomain)
          next if label.empty?

          prefix = label.split(/[-\d]/).first.to_s
          prefixes[prefix] += 1 unless prefix.empty?

          if (match = label.match(/\A([a-z][a-z0-9-]*?)(\d+)\z/i))
            numbered[match[1]] << match[2].to_i
          end

          ENV_HINTS.each { |hint| environments[prefix] << hint if label.include?(hint) }
          REGION_HINTS.each { |hint| regions[prefix] << hint if label.include?(hint) }
        rescue StandardError
          nil
        end

        {
          prefixes: prefixes,
          numbering: numbered.transform_values(&:uniq),
          environments: environments.transform_values { |values| values.to_a.sort },
          regions: regions.transform_values { |values| values.to_a.sort }
        }
      rescue StandardError
        {}
      end

      def generate
        candidates = {}
        @patterns.fetch(:prefixes, {}).each do |prefix, count|
          baseline = baseline_score(prefix, count)
          add_candidate(candidates, "#{prefix}.#{@domain}", baseline)

          next_number = Array(@patterns.dig(:numbering, prefix)).max.to_i + 1
          add_candidate(candidates, "#{prefix}#{next_number}.#{@domain}", [baseline + 0.15, 1.0].min)
          add_candidate(candidates, "#{prefix}#{next_number + 1}.#{@domain}", [baseline + 0.1, 1.0].min)

          ENV_HINTS.each { |env| add_candidate(candidates, "#{prefix}-#{env}.#{@domain}", [baseline + env_bonus(prefix), 1.0].min) }
          REGION_HINTS.each { |region| add_candidate(candidates, "#{prefix}-#{region}.#{@domain}", [baseline + region_bonus(prefix), 1.0].min) }
        end

        candidates.map { |subdomain, confidence| { subdomain: subdomain, confidence: confidence.round(2) } }
                  .sort_by { |entry| [-entry[:confidence], entry[:subdomain]] }
      rescue StandardError
        []
      end

      def top_candidates(n: 200)
        generate.first(n.to_i.positive? ? n.to_i : 200)
      rescue StandardError
        []
      end

      private

      def extract_label(subdomain)
        host = subdomain.to_s.downcase
        return "" unless host.end_with?(".#{@domain}")

        host.sub(/\.#{Regexp.escape(@domain)}\z/, "")
      rescue StandardError
        ""
      end

      def add_candidate(candidates, subdomain, confidence)
        return if subdomain == @domain || @known.include?(subdomain)

        candidates[subdomain] = [candidates[subdomain].to_f, confidence.to_f].max
      rescue StandardError
        nil
      end

      def baseline_score(prefix, count)
        base = ASRFacet::Engines::PermutationEngine::PREFIXES.include?(prefix) ? 0.4 : 0.25
        [base + [count.to_i * 0.08, 0.45].min, 0.95].min
      rescue StandardError
        0.2
      end

      def env_bonus(prefix)
        Array(@patterns.dig(:environments, prefix)).any? ? 0.2 : 0.08
      rescue StandardError
        0.08
      end

      def region_bonus(prefix)
        Array(@patterns.dig(:regions, prefix)).any? ? 0.18 : 0.07
      rescue StandardError
        0.07
      end
    end
  end
end
