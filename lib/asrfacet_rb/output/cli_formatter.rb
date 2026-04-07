# Part of ASRFacet-Rb - authorized testing only
require "colorize"
require "tty-table"

module ASRFacet
  module Output
    class CliFormatter < BaseFormatter
      def format(results)
        payload = payload_for(results)
        store = payload[:store]
        sections = []
        sections << overview_section(payload)
        sections << table_section("Subdomains", ["Host"], Array(store[:subdomains]).sort.map { |host| [host] }, :primary, meaning_for("subdomains"))
        sections << table_section("Open Ports", ["Host", "Port", "Service", "Banner"], port_rows(store), :orange, meaning_for("open_ports"))
        sections << table_section("HTTP Exposure", ["Host", "Status", "Title", "Technologies"], http_rows(store), :violet, meaning_for("http_responses"))
        sections << findings_section(store)
        sections << top_assets_section(payload[:top_assets])
        sections << table_section("JavaScript and SPA Endpoints", ["Source", "Endpoint"], endpoint_rows(payload, store), :violet, meaning_for("js_endpoints"))
        sections << table_section("DNS Highlights", ["Host", "Type", "Value"], dns_rows(store), :info, meaning_for("dns"))
        sections << table_section("Correlations", ["Type", "Summary"], correlation_rows(payload), :success, meaning_for("correlations"))
        sections << recommendations_section(payload)
        sections << artifact_section(payload)
        sections.reject(&:empty?).join("\n\n")
      rescue StandardError
        ""
      end

      private

      def overview_section(payload)
        counts = counts_for(payload[:store])
        summary_rows = [
          ["Target", primary_target(payload[:store])],
          ["Generated", payload.dig(:meta, :generated_at).to_s],
          ["Subdomains", counts[:subdomains]],
          ["Resolved IPs", counts[:ips]],
          ["Open Ports", counts[:open_ports]],
          ["Web Responses", counts[:http_responses]],
          ["Findings", counts[:findings]],
          ["Output Root", payload.dig(:meta, :output_directory).to_s]
        ]
        narrative = summary_narrative(payload).map { |line| "  - #{line}" }.join("\n")
        "#{heading('Scan Overview', :primary)}\n#{TTY::Table.new(rows: summary_rows).render(:unicode)}\n\nWhat It Means:\n#{narrative}"
      rescue StandardError
        ""
      end

      def findings_section(store)
        findings = Array(store[:findings]).sort_by do |finding|
          ASRFacet::Core::Severity::ORDER.index(finding[:severity]) || 999
        end
        return "" if findings.empty?

        rows = findings.map do |finding|
          severity = finding[:severity].to_s.upcase
          color = ASRFacet::Core::Severity::COLORS[finding[:severity]] || ASRFacet::Colors.terminal(:white)
          [
            finding[:title].to_s.colorize(color),
            severity.colorize(color),
            finding[:host],
            finding[:description],
            finding[:remediation]
          ]
        end

        "#{heading('Findings', :danger)}\n#{meaning_for('findings')}\n#{TTY::Table.new(header: ['Title', 'Severity', 'Host', 'Description', 'Recommendation'], rows: rows).render(:unicode)}"
      rescue StandardError
        ""
      end

      def top_assets_section(top_assets)
        rows = Array(top_assets).map do |asset|
          [asset[:host], asset[:total_score], Array(asset[:matched_rules]).join(", ")]
        end
        return "" if rows.empty?

        "#{heading('Top Targets', :success)}\nThese assets scored highly because they expose multiple signals worth deeper manual review.\n#{TTY::Table.new(header: ['Host', 'Score', 'Matched Rules'], rows: rows).render(:unicode)}"
      rescue StandardError
        ""
      end

      def recommendations_section(payload)
        lines = recommendations_for(payload)
        return "" if lines.empty?

        "#{heading('Recommended Next Steps', :warning)}\n#{lines.map { |line| "  - #{line}" }.join("\n")}"
      rescue StandardError
        ""
      end

      def artifact_section(payload)
        rows = artifact_rows(payload)
        return "" if rows.empty?

        "#{heading('Stored Artifacts', :info)}\nThese files are kept on disk so the run can be reviewed later without rerunning the scan.\n#{TTY::Table.new(header: ['Artifact', 'Path'], rows: rows).render(:unicode)}"
      rescue StandardError
        ""
      end

      def table_section(title, headers, rows, color_name, meaning)
        return "" if rows.empty?

        "#{heading(title, color_name)}\n#{meaning}\n#{TTY::Table.new(header: headers, rows: rows).render(:unicode)}"
      rescue StandardError
        ""
      end

      def port_rows(store)
        Array(store[:open_ports]).sort_by { |entry| [entry[:host].to_s, entry[:port].to_i] }.map do |entry|
          [entry[:host], entry[:port], entry[:service], entry[:banner].to_s[0, 80]]
        end
      rescue StandardError
        []
      end

      def http_rows(store)
        Array(store[:http_responses]).sort_by { |entry| entry[:host].to_s }.map do |entry|
          [entry[:host], entry[:status] || entry[:status_code], entry[:title], Array(entry[:technologies]).join(", ")]
        end
      rescue StandardError
        []
      end

      def endpoint_rows(payload, store)
        js_rows = Array(payload.dig(:js_endpoints, :endpoints_found)).map { |endpoint| ["javascript", endpoint] }
        spa_rows = Array(store[:spa_endpoints]).map { |entry| [entry[:discovered_from], "#{entry[:method]} #{entry[:url]}"] }
        (js_rows + spa_rows).uniq
      rescue StandardError
        []
      end

      def dns_rows(store)
        Array(store[:dns]).first(25).map { |entry| [entry[:host], entry[:type], entry[:value]] }
      rescue StandardError
        []
      end

      def correlation_rows(payload)
        Array(payload[:correlations]).map do |entry|
          item = symbolize_keys(entry)
          [item[:type], item.reject { |key, _value| key == :type }.map { |key, value| "#{key}=#{value}" }.join(", ")]
        end
      rescue StandardError
        []
      end

      def heading(text, color_name)
        text.to_s.colorize(ASRFacet::Colors.terminal(color_name))
      rescue StandardError
        text.to_s
      end
    end
  end
end
