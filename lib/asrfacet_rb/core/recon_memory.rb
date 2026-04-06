# Part of ASRFacet-Rb - authorized testing only
require "fileutils"
require "json"
require "time"

module ASRFacet
  module Core
    class ReconMemory
      attr_reader :data, :path

      def initialize(domain, base_dir: nil)
        @mutex = Mutex.new
        @domain = domain.to_s.downcase
        memory_dir = base_dir || File.join(Dir.home, ".asrfacet_rb", "memory")
        @path = File.join(memory_dir, "#{sanitize_filename(@domain)}.json")
        @data = load_or_init
      rescue StandardError
        @mutex = Mutex.new
        @domain = domain.to_s.downcase
        @path = ""
        @data = load_or_init
      end

      def load_or_init
        parsed = if !@path.to_s.empty? && File.file?(@path)
                   JSON.parse(File.read(@path), symbolize_names: true)
                 else
                   {}
                 end

        default_state.merge(symbolize_keys(parsed)) do |_key, old_value, new_value|
          if old_value.is_a?(Hash) && new_value.is_a?(Hash)
            old_value.merge(new_value)
          else
            new_value
          end
        end
      rescue StandardError
        default_state
      end

      def record_scan(results_hash)
        results = symbolize_keys(results_hash)
        snapshot = build_snapshot(results)
        scanned_at = Time.now.iso8601

        @mutex.synchronize do
          @data[:scans] << {
            scanned_at: scanned_at,
            engines_run: results.keys.map(&:to_s).sort,
            subdomain_count: snapshot[:subdomains].count,
            ip_count: snapshot[:ips].count,
            service_count: snapshot[:open_ports].count,
            finding_count: snapshot[:findings].count,
            new_assets: {
              subdomains: snapshot[:subdomains] - Array(@data.dig(:last_results, :subdomains)),
              ips: snapshot[:ips] - Array(@data.dig(:last_results, :ips))
            },
            open_ports: snapshot[:open_ports],
            findings: snapshot[:findings],
            certs: snapshot[:certs]
          }
          @data[:scans] = @data[:scans].last(50)

          merge_inventory!(:subdomain, snapshot[:subdomains], scanned_at)
          merge_inventory!(:ip, snapshot[:ips], scanned_at)
          merge_inventory!(:service, snapshot[:open_ports], scanned_at) do |entry|
            { id: "#{entry[:host]}:#{entry[:port]}", data: entry }
          end
          merge_inventory!(:asn, snapshot[:asn], scanned_at) do |entry|
            { id: entry[:asn].to_s.empty? ? entry[:ip].to_s : entry[:asn].to_s, data: entry }
          end

          @data[:known_subdomains] = ((@data[:known_subdomains] || []) + snapshot[:subdomains]).uniq.sort
          @data[:known_ips] = ((@data[:known_ips] || []) + snapshot[:ips]).uniq.sort
          @data[:known_services] = ((@data[:known_services] || []) + snapshot[:open_ports].map { |entry| "#{entry[:host]}:#{entry[:port]}" }).uniq.sort
          @data[:last_seen] = scanned_at
          @data[:last_results] = snapshot
          save_unlocked
        end
      rescue StandardError
        nil
      end

      def record_failure(engine_name, reason)
        @mutex.synchronize do
          @data[:failed_engines] ||= []
          @data[:failed_engines] << {
            engine: engine_name.to_s,
            reason: reason.to_s,
            at: Time.now.iso8601
          }
          @data[:failed_engines] = @data[:failed_engines].last(100)
          save_unlocked
        end
      rescue StandardError
        nil
      end

      def known?(subdomain)
        Array(@data[:known_subdomains]).map(&:to_s).include?(subdomain.to_s.downcase)
      rescue StandardError
        false
      end

      def save
        @mutex.synchronize { save_unlocked }
      rescue StandardError
        nil
      end

      def new_since_last_scan(current_subdomains)
        current = Array(current_subdomains).map { |entry| entry.to_s.downcase }.reject(&:empty?).uniq.sort
        previous = Array(@data.dig(:last_results, :subdomains)).map { |entry| entry.to_s.downcase }.reject(&:empty?).uniq.sort
        current - previous
      rescue StandardError
        []
      end

      private

      def default_state
        {
          domain: @domain,
          first_seen: Time.now.iso8601,
          last_seen: Time.now.iso8601,
          scans: [],
          inventory: {
            subdomain: {},
            ip: {},
            service: {},
            asn: {}
          },
          known_subdomains: [],
          known_ips: [],
          known_services: [],
          failed_engines: [],
          notes: [],
          last_results: {
            subdomains: [],
            ips: [],
            open_ports: [],
            findings: [],
            certs: [],
            asn: []
          }
        }
      rescue StandardError
        {}
      end

      def build_snapshot(results)
        {
          subdomains: Array(results[:subdomains]).map { |entry| entry.to_s.downcase }.reject(&:empty?).uniq.sort,
          ips: collect_ips(results),
          open_ports: Array(results[:open_ports]).map { |entry| symbolize_keys(entry).slice(:host, :port, :service) }.uniq.sort_by { |entry| [entry[:host].to_s, entry[:port].to_i] },
          findings: Array(results[:findings]).map { |entry| symbolize_keys(entry).slice(:host, :title, :severity) }.uniq.sort_by { |item| [item[:host].to_s, item[:title].to_s] },
          certs: Array(results[:certs]).map { |entry| symbolize_keys(entry).slice(:host, :subject, :issuer, :not_after, :expired, :sans) }.uniq.sort_by { |item| item[:host].to_s },
          asn: Array(results[:asn]).map { |entry| symbolize_keys(entry) }.uniq.sort_by { |item| [item[:asn].to_s, item[:ip].to_s] }
        }
      rescue StandardError
        { subdomains: [], ips: [], open_ports: [], findings: [], certs: [], asn: [] }
      end

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

      def merge_inventory!(type, entries, scanned_at)
        @data[:inventory] ||= {}
        bucket = (@data[:inventory][type.to_sym] ||= {})

        Array(entries).each do |entry|
          prepared = if block_given?
                       yield(entry)
                     else
                       { id: entry.to_s, data: {} }
                     end
          asset_id = prepared[:id].to_s
          next if asset_id.empty?

          record = bucket[asset_id] || {
            id: asset_id,
            type: type.to_sym,
            first_seen: scanned_at,
            last_seen: scanned_at,
            data: {}
          }
          record[:last_seen] = scanned_at
          record[:data] = merge_hash(record[:data], prepared[:data] || {})
          bucket[asset_id] = record
        end
      rescue StandardError
        nil
      end

      def save_unlocked
        return nil if @path.to_s.empty?

        FileUtils.mkdir_p(File.dirname(@path))
        File.write(@path, JSON.pretty_generate(@data))
        @path
      rescue StandardError
        nil
      end

      def sanitize_filename(value)
        safe = value.to_s.downcase.gsub(/[^a-z0-9._-]+/, "_").gsub(/\A_+|_+\z/, "")
        safe.empty? ? "default" : safe
      rescue StandardError
        "default"
      end

      def merge_hash(left, right)
        symbolize_keys(left).merge(symbolize_keys(right))
      rescue StandardError
        symbolize_keys(right)
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
