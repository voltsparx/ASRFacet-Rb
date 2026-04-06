# Part of ASRFacet-Rb — authorized testing only
require "time"

module ASRFacet
  module Engines
    class MonitoringEngine
      attr_reader :memory

      def initialize(domain)
        @memory = ASRFacet::Core::ReconMemory.new(domain)
      rescue StandardError
        @memory = ASRFacet::Core::ReconMemory.new(domain.to_s)
      end

      def diff(current_results)
        current = symbolize_keys(current_results)
        {
          new_subdomains: new_subdomains(current),
          removed_subdomains: removed_subdomains(current),
          new_findings: new_findings(current),
          new_open_ports: new_open_ports(current),
          cert_changes: cert_changes(current),
          changed_at: Time.now.iso8601
        }
      rescue StandardError
        { new_subdomains: [], removed_subdomains: [], new_findings: [], new_open_ports: [], cert_changes: [], changed_at: Time.now.iso8601 }
      end

      def new_subdomains(current)
        @memory.new_since_last_scan(current[:subdomains] || [])
      rescue StandardError
        []
      end

      def removed_subdomains(current)
        Array(@memory.data[:known_subdomains]) - Array(current[:subdomains] || [])
      rescue StandardError
        []
      end

      def new_open_ports(current)
        previous = Array(@memory.data[:scans]).last&.dig(:open_ports) || []
        current_ports = Array(current[:open_ports]).map { |entry| symbolize_keys(entry).slice(:host, :port, :service) }
        current_ports - Array(previous).map { |entry| symbolize_keys(entry) }
      rescue StandardError
        []
      end

      def report_diff(diff_result)
        diff = symbolize_keys(diff_result)
        [
          "[+] NEW SUBDOMAINS\n#{format_lines(diff[:new_subdomains])}",
          "[-] REMOVED SUBDOMAINS\n#{format_lines(diff[:removed_subdomains])}",
          "[!] NEW FINDINGS\n#{format_lines(Array(diff[:new_findings]).map { |finding| "#{finding[:host]} - #{finding[:title]}" })}",
          "[~] PORT CHANGES\n#{format_lines(Array(diff[:new_open_ports]).map { |port| "#{port[:host]}:#{port[:port]} (#{port[:service]})" })}"
        ].join("\n\n")
      rescue StandardError
        ""
      end

      private

      def new_findings(current)
        previous = Array(@memory.data.dig(:last_results, :findings))
        current_findings = Array(current[:findings]).map { |entry| symbolize_keys(entry).slice(:host, :title, :severity) }
        current_findings - previous.map { |entry| symbolize_keys(entry) }
      rescue StandardError
        []
      end

      def cert_changes(current)
        previous = Array(@memory.data.dig(:last_results, :certs)).map { |entry| symbolize_keys(entry) }
        current_certs = Array(current[:certs]).map { |entry| symbolize_keys(entry).slice(:host, :subject, :issuer, :not_after, :expired, :sans) }

        current_certs.filter_map do |cert|
          old = previous.find { |entry| entry[:host].to_s == cert[:host].to_s }
          next if old == cert

          { host: cert[:host], previous: old, current: cert }
        end
      rescue StandardError
        []
      end

      def format_lines(lines)
        values = Array(lines)
        return "(none)" if values.empty?

        values.map(&:to_s).join("\n")
      rescue StandardError
        "(none)"
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
