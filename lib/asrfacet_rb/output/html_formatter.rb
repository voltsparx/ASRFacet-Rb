# Part of ASRFacet-Rb — authorized testing only
require "cgi"
require "json"
require "time"

module ASRFacet
  module Output
    class HtmlFormatter < BaseFormatter
      def format(results)
        payload = payload_for(results)
        data = payload[:store]
        generated_at = Time.now.iso8601

        <<~HTML
          <!doctype html>
          <html lang="en">
          <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>ASRFacet-Rb Report</title>
            <style>
              :root { color-scheme: light; --ink: #1f1a17; --muted: #5d5248; --paper: #fffdf9; --wash: #f4efe6; --accent: #1f3a5f; --line: #ddcfbb; --critical: #a2201a; --high: #d9480f; --medium: #d4a017; --low: #1d4ed8; --info: #6b7280; --good: #2f9e44; --warn: #e67700; --bad: #c92a2a; }
              * { box-sizing: border-box; }
              body { margin: 0; font-family: Georgia, "Times New Roman", serif; background: linear-gradient(180deg, var(--wash) 0%, #faf8f4 100%); color: var(--ink); }
              header { padding: 2rem; background: var(--accent); color: #fff7e8; }
              header h1 { margin: 0 0 0.5rem; font-size: 2rem; letter-spacing: 0.04em; }
              header p { margin: 0.35rem 0; color: #efe3d0; }
              main { max-width: 1180px; margin: 0 auto; padding: 1.5rem; }
              details { background: rgba(255,255,255,0.9); border: 1px solid var(--line); border-radius: 14px; padding: 1rem 1.25rem; margin-bottom: 1rem; box-shadow: 0 10px 30px rgba(31,26,23,0.08); }
              summary { cursor: pointer; font-weight: 700; }
              table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
              th, td { text-align: left; padding: 0.65rem; border-bottom: 1px solid #e7dbc7; vertical-align: top; }
              th { background: #f5ecdf; }
              .finding-grid, .score-grid { display: grid; gap: 1rem; margin-top: 1rem; }
              .finding, .score-card { border-left: 6px solid #6c757d; padding: 1rem; border-radius: 12px; background: #fff; }
              .finding.critical { border-color: var(--critical); }
              .finding.high { border-color: var(--high); }
              .finding.medium { border-color: var(--medium); }
              .finding.low { border-color: var(--low); }
              .finding.info { border-color: var(--info); }
              .score-card { border-color: var(--accent); }
              .pill { display: inline-block; margin: 0.2rem 0.4rem 0 0; padding: 0.15rem 0.55rem; background: #f5ecdf; border-radius: 999px; font-size: 0.9rem; }
              .meta { color: var(--muted); font-size: 0.95rem; }
              footer { text-align: center; padding: 1.5rem; color: var(--muted); }
              button.toggle-all { margin-top: 1rem; background: #fff7e8; border: 1px solid #e7dbc7; border-radius: 999px; padding: 0.55rem 1rem; cursor: pointer; }
              code, pre { font-family: Consolas, monospace; }
              code { background: #f5ecdf; padding: 0.1rem 0.3rem; border-radius: 4px; }
              pre { white-space: pre-wrap; word-break: break-word; }
              .change.new { color: var(--good); }
              .change.removed { color: var(--bad); }
              .change.changed { color: var(--warn); }
            </style>
          </head>
          <body>
            <header>
              <h1>ASRFacet-Rb Report</h1>
              <p class="meta">Authorized testing output for #{escape(primary_target(data))}</p>
              <p class="meta">Scope-aware reconnaissance with change tracking and graph pivots</p>
              <button class="toggle-all" type="button" onclick="toggleSections()">Toggle Sections</button>
            </header>
            <main>
              #{section_top_targets(payload[:top_assets])}
              #{section_change_summary(payload[:diff])}
              #{section_table("Subdomains", ["Host"], Array(data[:subdomains]).sort.map { |host| [host] }, open: true)}
              #{section_table("Open Ports", ["Host", "Port", "Service", "Banner"], Array(data[:open_ports]).sort_by { |entry| [entry[:host].to_s, entry[:port].to_i] }.map { |entry| [entry[:host], entry[:port], entry[:service], entry[:banner]] })}
              #{section_table("Technologies", ["Host", "Technology", "CDN"], Array(data[:http_responses]).flat_map { |entry| Array(entry[:technologies]).map { |tech| [entry[:host], tech, entry[:cdn]] } })}
              #{section_js_endpoints(payload[:js_endpoints])}
              #{section_findings(Array(data[:findings]))}
              #{section_knowledge_graph(payload[:graph])}
              #{section_table("Correlations", ["Type", "Summary"], Array(payload[:correlations]).map { |entry| [entry[:type], correlation_summary(entry)] })}
              #{section_pretty("DNS", data[:dns])}
              #{section_pretty("Certificates", data[:certs])}
              #{section_pretty("WHOIS", data[:whois])}
              #{section_pretty("ASN", data[:asn])}
              #{section_pretty("Probabilistic Subdomain Hints", payload[:probabilistic_subdomains])}
            </main>
            <footer>Generated at #{escape(generated_at)} by ASRFacet-Rb</footer>
            <script>
              function toggleSections() {
                document.querySelectorAll('details').forEach(function(section) {
                  section.open = !section.open;
                });
              }
            </script>
          </body>
          </html>
        HTML
      rescue StandardError
        "<html><body><p>Unable to render report.</p></body></html>"
      end

      private

      def section_table(title, headers, rows, open: false)
        body = if rows.empty?
                 "<p>No data collected.</p>"
               else
                 "<table><thead><tr>#{headers.map { |header| "<th>#{escape(header)}</th>" }.join}</tr></thead><tbody>#{rows.map { |row| "<tr>#{row.map { |value| "<td>#{escape(value)}</td>" }.join}</tr>" }.join}</tbody></table>"
               end

        %(<details#{open ? " open" : ""}><summary>#{escape(title)}</summary>#{body}</details>)
      rescue StandardError
        ""
      end

      def section_findings(findings)
        ordered = findings.sort_by { |finding| ASRFacet::Core::Severity::ORDER.index(finding[:severity]) || 999 }
        body = if ordered.empty?
                 "<p>No findings collected.</p>"
               else
                 %(<div class="finding-grid">#{ordered.map { |finding| finding_card(finding) }.join}</div>)
               end

        %(<details open><summary>Findings</summary>#{body}</details>)
      rescue StandardError
        ""
      end

      def section_top_targets(top_assets)
        assets = Array(top_assets)
        body = if assets.empty?
                 "<p>No scored assets available.</p>"
               else
                 %(<div class="score-grid">#{assets.map { |asset| score_card(asset) }.join}</div>)
               end
        %(<details open><summary>Top Targets</summary>#{body}</details>)
      rescue StandardError
        ""
      end

      def section_change_summary(diff)
        data = symbolize_keys(diff || {})
        return "" if data.empty?

        body = []
        body << %(<p class="change new"><strong>New subdomains:</strong> #{escape(Array(data[:new_subdomains]).join(", "))}</p>)
        body << %(<p class="change removed"><strong>Removed subdomains:</strong> #{escape(Array(data[:removed_subdomains]).join(", "))}</p>)
        body << %(<p class="change changed"><strong>New findings:</strong> #{escape(Array(data[:new_findings]).map { |finding| "#{finding[:host]} - #{finding[:title]}" }.join(", "))}</p>)
        body << %(<p class="change changed"><strong>Port changes:</strong> #{escape(Array(data[:new_open_ports]).map { |port| "#{port[:host]}:#{port[:port]}" }.join(", "))}</p>)
        %(<details open><summary>Change Summary</summary>#{body.join}</details>)
      rescue StandardError
        ""
      end

      def section_knowledge_graph(graph)
        graph_data = symbolize_keys(graph || {})
        return "" if graph_data.empty?

        rows = Array(graph_data[:edges]).map do |edge|
          [edge[:from], edge[:relation], edge[:to]]
        end
        rows = [["(none)", "(none)", "(none)"]] if rows.empty?
        node_rows = Array(graph_data[:nodes]).map { |node| [node[:id], node[:type], JSON.generate(node[:data] || {})] }
        node_rows = [["(none)", "(none)", "(none)"]] if node_rows.empty?
        body = "#{section_table_inner(["Node", "Type", "Data"], node_rows)}#{section_table_inner(["From", "Relation", "To"], rows)}"
        %(<details><summary>Knowledge Graph</summary><h3>Nodes</h3>#{body}</details>)
      rescue StandardError
        ""
      end

      def section_js_endpoints(js_endpoints)
        data = symbolize_keys(js_endpoints || {})
        return "" if data.empty?

        rows = Array(data[:endpoints_found]).map { |endpoint| [endpoint] }
        rows = [["(none)"]] if rows.empty?
        body = []
        body << "<p><strong>JS files scanned:</strong> #{escape(data[:js_files_scanned])}</p>"
        body << "<p><strong>Potential secrets:</strong> #{escape(data[:potential_secrets])}</p>"
        body << section_table_inner(["Endpoint"], rows)
        body << section_findings(Array(data[:findings]).map { |finding| symbolize_keys(finding) }.map { |finding| finding })
        %(<details><summary>JavaScript Endpoints</summary>#{body.join}</details>)
      rescue StandardError
        ""
      end

      def section_pretty(title, data)
        formatted = JSON.pretty_generate(data || [])
        %(<details><summary>#{escape(title)}</summary><pre><code>#{escape(formatted)}</code></pre></details>)
      rescue StandardError
        ""
      end

      def section_table_inner(headers, rows)
        "<table><thead><tr>#{headers.map { |header| "<th>#{escape(header)}</th>" }.join}</tr></thead><tbody>#{rows.map { |row| "<tr>#{row.map { |value| "<td>#{escape(value)}</td>" }.join}</tr>" }.join}</tbody></table>"
      rescue StandardError
        ""
      end

      def finding_card(finding)
        severity = finding[:severity].to_s
        %(
          <article class="finding #{escape(severity)}">
            <h3>#{escape(finding[:title])}</h3>
            <p><strong>Severity:</strong> #{escape(severity.upcase)}</p>
            <p><strong>Host:</strong> #{escape(finding[:host])}</p>
            <p><strong>Description:</strong> #{escape(finding[:description])}</p>
            <p><strong>Remediation:</strong> #{escape(finding[:remediation])}</p>
          </article>
        )
      rescue StandardError
        ""
      end

      def score_card(asset)
        rules = Array(asset[:matched_rules]).map { |rule| %(<span class="pill">#{escape(rule)}</span>) }.join
        %(
          <article class="score-card">
            <h3>#{escape(asset[:host])}</h3>
            <p><strong>Score:</strong> #{escape(asset[:total_score])}</p>
            <div>#{rules}</div>
          </article>
        )
      rescue StandardError
        ""
      end

      def primary_target(data)
        Array(data[:subdomains]).first || "target"
      rescue StandardError
        "target"
      end

      def correlation_summary(entry)
        item = symbolize_keys(entry)
        item.reject { |key, _value| key == :type }.map { |key, value| "#{key}=#{value}" }.join(", ")
      rescue StandardError
        ""
      end

      def escape(value)
        CGI.escapeHTML(value.to_s)
      rescue StandardError
        ""
      end
    end
  end
end
