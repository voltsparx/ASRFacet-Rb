# Part of ASRFacet-Rb — authorized testing only
require "colorize"
require "tty-table"

module ASRFacet::Output
  class CliFormatter < BaseFormatter
    def format(results)
      payload = payload_for(results)
      store = payload[:store]
      [
        print_subdomains(store),
        print_ports(store),
        print_technologies(store),
        print_findings(store),
        print_top_assets(payload[:top_assets])
      ].reject(&:empty?).join("\n\n")
    rescue StandardError
      ""
    end

    def print_subdomains(results)
      rows = Array(results[:subdomains]).sort.map { |host| [host] }
      return "" if rows.empty?

      "Subdomains\n#{TTY::Table.new(header: ["Host"], rows: rows).render(:unicode)}"
    rescue StandardError
      ""
    end

    def print_ports(results)
      rows = Array(results[:open_ports]).sort_by { |entry| [entry[:host].to_s, entry[:port].to_i] }.map do |entry|
        [entry[:host], entry[:port], entry[:service], entry[:banner].to_s[0, 60]]
      end
      return "" if rows.empty?

      "Open Ports\n#{TTY::Table.new(header: %w[Host Port Service Banner], rows: rows).render(:unicode)}"
    rescue StandardError
      ""
    end

    def print_technologies(results)
      rows = Array(results[:http_responses]).flat_map do |entry|
        Array(entry[:technologies]).map { |tech| [entry[:host], tech, entry[:cdn].to_s] }
      end
      return "" if rows.empty?

      "Technologies\n#{TTY::Table.new(header: ["Host", "Technology", "CDN"], rows: rows).render(:unicode)}"
    rescue StandardError
      ""
    end

    def print_findings(results)
      findings = Array(results[:findings]).sort_by do |finding|
        ASRFacet::Core::Severity::ORDER.index(finding[:severity]) || 999
      end
      return "" if findings.empty?

      rows = findings.map do |finding|
        severity = finding[:severity].to_s.upcase
        color = ASRFacet::Core::Severity::COLORS[finding[:severity]] || :white
        [
          finding[:title].to_s.colorize(color),
          severity.colorize(color),
          finding[:host],
          finding[:description],
          finding[:remediation]
        ]
      end

      "Findings\n#{TTY::Table.new(header: ["Title", "Severity", "Host", "Description", "Remediation"], rows: rows).render(:unicode)}"
    rescue StandardError
      ""
    end

    def print_top_assets(top_assets)
      rows = Array(top_assets).map do |asset|
        [asset[:host], asset[:total_score], Array(asset[:matched_rules]).join(", ")]
      end
      return "" if rows.empty?

      "Top Targets\n#{TTY::Table.new(header: ["Host", "Score", "Matched Rules"], rows: rows).render(:unicode)}"
    rescue StandardError
      ""
    end
  end
end
