# Part of ASRFacet-Rb — authorized testing only
require "colorize"
require "tty-table"

module ASRFacet::Output
  class CliFormatter < BaseFormatter
    def format(results)
      [
        print_subdomains(results),
        print_ports(results),
        print_technologies(results),
        print_findings(results)
      ].reject(&:empty?).join("\n\n")
    rescue StandardError
      ""
    end

    def print_subdomains(results)
      rows = Array(results.to_h[:subdomains]).sort.map { |host| [host] }
      return "" if rows.empty?

      "Subdomains\n#{TTY::Table.new(header: ["Host"], rows: rows).render(:unicode)}"
    rescue StandardError
      ""
    end

    def print_ports(results)
      rows = Array(results.to_h[:open_ports]).sort_by { |entry| [entry[:host].to_s, entry[:port].to_i] }.map do |entry|
        [entry[:host], entry[:port], entry[:service], entry[:banner].to_s[0, 60]]
      end
      return "" if rows.empty?

      "Open Ports\n#{TTY::Table.new(header: %w[Host Port Service Banner], rows: rows).render(:unicode)}"
    rescue StandardError
      ""
    end

    def print_technologies(results)
      rows = Array(results.to_h[:http_responses]).flat_map do |entry|
        Array(entry[:technologies]).map { |tech| [entry[:host], tech, entry[:cdn].to_s] }
      end
      return "" if rows.empty?

      "Technologies\n#{TTY::Table.new(header: ["Host", "Technology", "CDN"], rows: rows).render(:unicode)}"
    rescue StandardError
      ""
    end

    def print_findings(results)
      findings = Array(results.to_h[:findings]).sort_by do |finding|
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
  end
end
