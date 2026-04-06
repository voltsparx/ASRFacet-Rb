# Part of ASRFacet-Rb — authorized testing only
require "fileutils"
require "json"
require "time"

module ASRFacet
  module Core
    class ReconMemory
      attr_reader :data, :path

      def initialize(domain)
        @domain = domain.to_s.downcase
        @path = File.join(Dir.home, ".asrfacet_rb", "memory", "#{@domain.gsub('.', '_')}.json")
        @data = load_or_init
      rescue StandardError
        @domain = domain.to_s.downcase
        @path = ""
        @data = load_or_init
      end

      def load_or_init
        if File.file?(@path)
          parsed = JSON.parse(File.read(@path), symbolize_names: true)
          parsed[:domain] ||= @domain
          parsed[:scans] ||= []
          parsed[:known_subdomains] ||= []
          parsed[:known_ips] ||= []
          parsed[:failed_engines] ||= []
          parsed[:notes] ||= []
          parsed[:last_results] ||= {}
          parsed
        else
          {
            domain: @domain,
            first_seen: Time.now.iso8601,
            last_seen: Time.now.iso8601,
            scans: [],
            known_subdomains: [],
            known_ips: [],
            failed_engines: [],
            notes: [],
            last_results: {}
          }
        end
      rescue StandardError
        {
          domain: @domain,
          first_seen: Time.now.iso8601,
          last_seen: Time.now.iso8601,
          scans: [],
          known_subdomains: [],
          known_ips: [],
          failed_engines: [],
          notes: [],
          last_results: {}
        }
      end

      def record_scan(results_hash)
        results = symbolize_keys(results_hash)
        subdomains = Array(results[:subdomains]).map(&:to_s).uniq.sort
        ips = collect_ips(results)
        findings = Array(results[:findings]).map { |finding| symbolize_keys(finding).slice(:host, :title, :severity) }
        open_ports = Array(results[:open_ports]).map { |entry| symbolize_keys(entry).slice(:host, :port, :service) }
        certs = Array(results[:certs]).map { |entry| symbolize_keys(entry).slice(:host, :subject, :issuer, :not_after, :expired, :sans) }

        @data[:scans] << {
          scanned_at: Time.now.iso8601,
          engines_run: results.keys.map(&:to_s).sort,
          subdomain_count: subdomains.count,
          finding_count: findings.count,
          open_ports: open_ports,
          findings: findings,
          certs: certs
        }
        @data[:known_subdomains] = ((@data[:known_subdomains] || []) + subdomains).uniq.sort
        @data[:known_ips] = ((@data[:known_ips] || []) + ips).uniq.sort
        @data[:last_seen] = Time.now.iso8601
        @data[:last_results] = {
          subdomains: subdomains,
          open_ports: open_ports,
          findings: findings,
          certs: certs
        }
        save
      rescue StandardError
        nil
      end

      def record_failure(engine_name, reason)
        @data[:failed_engines] ||= []
        @data[:failed_engines] << {
          engine: engine_name.to_s,
          reason: reason.to_s,
          at: Time.now.iso8601
        }
        save
      rescue StandardError
        nil
      end

      def known?(subdomain)
        Array(@data[:known_subdomains]).map(&:to_s).include?(subdomain.to_s.downcase)
      rescue StandardError
        false
      end

      def save
        FileUtils.mkdir_p(File.dirname(@path))
        File.write(@path, JSON.pretty_generate(@data))
        @path
      rescue StandardError
        nil
      end

      def new_since_last_scan(current_subdomains)
        Array(current_subdomains).map(&:to_s).uniq - Array(@data[:known_subdomains]).map(&:to_s)
      rescue StandardError
        []
      end

      private

      def collect_ips(results)
        direct_ips = Array(results[:ips]).map(&:to_s)
        dns_ips = Array(results[:dns]).filter_map do |record|
          entry = symbolize_keys(record)
          entry[:value].to_s if %i[a aaaa].include?(entry[:type].to_sym)
        end
        (direct_ips + dns_ips).uniq.sort
      rescue StandardError
        []
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
