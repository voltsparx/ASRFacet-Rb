# Part of ASRFacet-Rb - authorized testing only
require "cgi"
require "json"
require "time"

module ASRFacet
  module Output
    class HtmlFormatter < BaseFormatter
      def format(results)
        payload = payload_for(results)
        data = payload[:store]
        generated_at = payload.dig(:meta, :generated_at).to_s.empty? ? Time.now.utc.iso8601 : payload.dig(:meta, :generated_at)

        <<~HTML
          <!doctype html>
          <html lang="en">
          <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>ASRFacet-Rb Report</title>
            <style>
              :root { color-scheme: light; #{ASRFacet::Colors.css_variables} --accent: var(--primary); --critical: var(--danger); --good: var(--success); --warn: var(--orange); --bad: var(--danger); }
              * { box-sizing: border-box; }
              body { margin: 0; font-family: Georgia, "Times New Roman", serif; background: radial-gradient(circle at top, rgba(29,78,216,0.08), transparent 28%), linear-gradient(180deg, var(--wash) 0%, var(--paper) 100%); color: var(--ink); }
              header { padding: 2rem; background: linear-gradient(135deg, var(--primary) 0%, var(--violet) 100%); color: var(--white); }
              header h1 { margin: 0 0 0.4rem; font-size: 2.2rem; letter-spacing: 0.04em; }
              header p { margin: 0.35rem 0; }
              main { max-width: 1240px; margin: 0 auto; padding: 1.5rem; }
              details { background: rgba(255,255,255,0.94); border: 1px solid var(--line); border-radius: 16px; padding: 1rem 1.25rem; margin-bottom: 1rem; box-shadow: 0 12px 28px rgba(31,26,23,0.08); }
              summary { cursor: pointer; font-weight: 700; color: var(--primary); }
              .meta { color: var(--white); opacity: 0.95; }
              .muted { color: var(--muted); }
              .card-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-top: 1rem; }
              .card { background: var(--panel); border: 1px solid var(--line); border-radius: 16px; padding: 1rem; box-shadow: 0 8px 18px rgba(31,26,23,0.05); }
              .card h3 { margin: 0; font-size: 0.92rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); }
              .card p { margin: 0.45rem 0 0; font-size: 1.8rem; color: var(--ink); }
              .chart-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1rem; margin-top: 1rem; align-items: start; }
              .chart { background: var(--panel); border: 1px solid var(--line); border-radius: 16px; padding: 1rem; }
              .chart h3 { margin-top: 0; }
              table { width: 100%; border-collapse: collapse; margin-top: 1rem; background: var(--panel); }
              th, td { text-align: left; padding: 0.7rem; border-bottom: 1px solid var(--line); vertical-align: top; }
              th { background: var(--soft); }
              .finding-grid, .score-grid { display: grid; gap: 1rem; margin-top: 1rem; }
              .finding, .score-card { border-left: 6px solid var(--muted); padding: 1rem; border-radius: 12px; background: var(--panel); }
              .finding.critical { border-color: var(--danger); }
              .finding.high { border-color: var(--high); }
              .finding.medium { border-color: var(--warning); }
              .finding.low { border-color: var(--info); }
              .finding.info { border-color: var(--muted); }
              .score-card { border-color: var(--violet); }
              .pill { display: inline-block; margin: 0.2rem 0.4rem 0 0; padding: 0.15rem 0.55rem; background: var(--soft); border-radius: 999px; font-size: 0.9rem; color: var(--violet); }
              .callout { padding: 0.85rem 1rem; border-left: 4px solid var(--primary); background: rgba(255,255,255,0.7); border-radius: 8px; margin-top: 0.9rem; }
              .callout.warn { border-left-color: var(--warning); }
              .callout.good { border-left-color: var(--success); }
              .artifact-list { list-style: none; padding: 0; margin: 1rem 0 0; }
              .artifact-list li { margin-bottom: 0.5rem; }
              button.toggle-all { margin-top: 1rem; background: var(--white); border: 1px solid var(--line); border-radius: 999px; padding: 0.55rem 1rem; cursor: pointer; color: var(--primary); }
              code, pre { font-family: Consolas, monospace; }
              code { background: var(--soft); padding: 0.12rem 0.3rem; border-radius: 4px; }
              pre { white-space: pre-wrap; word-break: break-word; background: var(--panel); padding: 1rem; border-radius: 12px; border: 1px solid var(--line); }
              footer { text-align: center; padding: 1.5rem; color: var(--muted); }
              .legend { display: flex; flex-wrap: wrap; gap: 0.75rem; margin-top: 0.75rem; }
              .legend span { display: inline-flex; align-items: center; gap: 0.4rem; color: var(--muted); }
              .legend i { width: 12px; height: 12px; display: inline-block; border-radius: 50%; }
            </style>
          </head>
          <body>
            <header>
              <h1>ASRFacet-Rb Report</h1>
              <p class="meta">Authorized testing output for #{escape(primary_target(data))}</p>
              <p class="meta">Generated at #{escape(generated_at)} | Stored under #{escape(payload.dig(:meta, :output_directory))}</p>
              <p class="meta">Human-readable report with findings, explanations, recommendations, tables, charts, and artifact paths.</p>
              <button class="toggle-all" type="button" onclick="toggleSections()">Toggle Sections</button>
            </header>
            <main>
              #{section_overview(payload)}
              #{section_visual_summary(payload)}
              #{section_top_targets(payload[:top_assets])}
              #{section_change_summary(payload)}
              #{section_findings(Array(data[:findings]))}
              #{section_http_exposure(data[:http_responses])}
              #{section_table("Subdomains", "These are the hosts the scan believes belong to the authorized target surface.", ["Host"], Array(data[:subdomains]).sort.map { |host| [host] }, open: true)}
              #{section_table("Open Ports", "These are reachable TCP services that expand the external attack surface.", ["Host", "Port", "Service", "Banner"], Array(data[:open_ports]).sort_by { |entry| [entry[:host].to_s, entry[:port].to_i] }.map { |entry| [entry[:host], entry[:port], entry[:service], entry[:banner]] })}
              #{section_js_endpoints(payload[:js_endpoints], data[:spa_endpoints])}
              #{section_table("DNS Records", "These records explain how hostnames resolve and which support systems back the visible surface.", ["Host", "Type", "Value"], Array(data[:dns]).first(200).map { |entry| [entry[:host], entry[:type], entry[:value]] })}
              #{section_table("Certificates", "Certificate data often reveals related hostnames through SAN coverage and issuer metadata.", ["Field", "Value"], pretty_kv_rows(data[:certs]))}
              #{section_table("WHOIS and Ownership", "This section helps map ownership, registrars, and broader infrastructure context.", ["Field", "Value"], pretty_kv_rows(data[:whois]))}
              #{section_table("ASN Context", "ASN data links IP space to provider or organization-level infrastructure ownership.", ["Field", "Value"], pretty_kv_rows(data[:asn]))}
              #{section_table("Correlations", "Correlations connect assets that deserve to be triaged together during manual review.", ["Type", "Summary"], Array(payload[:correlations]).map { |entry| [entry[:type], correlation_summary(entry)] })}
              #{section_knowledge_graph(payload[:graph])}
              #{section_table("Probabilistic Subdomain Hints", "These are machine-assisted guesses that may be worth validating manually.", ["Host", "Score"], Array(payload[:probabilistic_subdomains]).map { |entry| [entry[:host] || entry[:subdomain], entry[:score] || entry[:probability]] })}
              #{section_table("Stored Artifacts", "These files were written automatically so the run can be reviewed later without rerunning it.", ["Artifact", "Path"], artifact_rows(payload))}
              #{section_table("Engine Errors", "These notes show sources or engines that failed or were skipped during the run.", ["Engine", "Reason"], Array(data[:errors]).map { |entry| [entry[:engine], entry[:reason]] })}
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

      def section_overview(payload)
        counts = counts_for(payload[:store])
        cards = [
          ["Subdomains", counts[:subdomains]],
          ["Resolved IPs", counts[:ips]],
          ["Open Ports", counts[:open_ports]],
          ["Web Responses", counts[:http_responses]],
          ["Findings", counts[:findings]],
          ["JS Endpoints", counts[:js_endpoints]],
          ["SPA Endpoints", counts[:spa_endpoints]],
          ["Correlations", counts[:correlations]]
        ]

        body = []
        body << %(<div class="card-grid">#{cards.map { |title, value| %(<article class="card"><h3>#{escape(title)}</h3><p>#{escape(value)}</p></article>) }.join}</div>)
        body << %(<div class="callout good"><strong>What this means:</strong> #{summary_narrative(payload).map { |line| escape(line) }.join(" ")}</div>)
        body << %(<div class="callout warn"><strong>Recommended next steps:</strong> #{recommendations_for(payload).map { |line| escape(line) }.join(" ")}</div>)
        %(<details open><summary>Executive Summary</summary>#{body.join}</details>)
      rescue StandardError
        ""
      end

      def section_visual_summary(payload)
        counts = counts_for(payload[:store])
        findings = Array(payload[:store][:findings])
        body = []
        body << %(<div class="chart-grid"><div class="chart"><h3>Exposure Line Graph</h3><p class="muted">This chart shows the overall growth of discovered surface across major categories.</p>#{line_chart_svg(counts)}</div><div class="chart"><h3>Finding Severity Pie Chart</h3><p class="muted">This chart shows how much of the finding set is concentrated in each severity band.</p>#{severity_pie_svg(findings)}#{severity_legend(findings)}</div></div>)
        %(<details open><summary>Charts and Visual Summary</summary>#{body.join}</details>)
      rescue StandardError
        ""
      end

      def section_http_exposure(entries)
        rows = Array(entries).map do |entry|
          [entry[:host], entry[:status] || entry[:status_code], entry[:title], Array(entry[:technologies]).join(", "), entry[:server] || entry[:cdn], entry[:url]]
        end
        section_table("HTTP Exposure", "These responses show what web content is reachable, which technologies appear present, and where deeper manual review should begin.", ["Host", "Status", "Title", "Technologies", "Server/CDN", "URL"], rows)
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

        %(<details open><summary>Findings</summary><p class="muted">Findings are heuristic flags, not automatic proof of exploitation. They are written to be human-readable so operators know what they mean and what to check next.</p>#{body}</details>)
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
        %(<details open><summary>Top Targets</summary><p class="muted">These assets bubbled up because they combine multiple signals that usually deserve faster manual attention.</p>#{body}</details>)
      rescue StandardError
        ""
      end

      def section_change_summary(payload)
        data = symbolize_keys(payload[:diff] || {})
        body = []
        body << %(<div class="callout"><strong>Summary:</strong> #{escape(payload[:change_summary].to_s.empty? ? "No change summary was generated for this run." : payload[:change_summary])}</div>)
        return %(<details><summary>Change Summary</summary>#{body.join}</details>) if data.empty?

        rows = []
        rows << ["New subdomains", Array(data[:new_subdomains]).join(", ")]
        rows << ["Removed subdomains", Array(data[:removed_subdomains]).join(", ")]
        rows << ["New findings", Array(data[:new_findings]).map { |finding| "#{finding[:host]} - #{finding[:title]}" }.join(", ")]
        rows << ["New open ports", Array(data[:new_open_ports]).map { |port| "#{port[:host]}:#{port[:port]}" }.join(", ")]
        body << section_table_inner(["Change Type", "Details"], rows)
        %(<details open><summary>Change Summary</summary>#{body.join}</details>)
      rescue StandardError
        ""
      end

      def section_js_endpoints(js_endpoints, spa_entries)
        data = symbolize_keys(js_endpoints || {})
        rows = Array(data[:endpoints_found]).map { |endpoint| ["javascript", endpoint] }
        rows += Array(spa_entries).map { |entry| [entry[:discovered_from], "#{entry[:method]} #{entry[:url]}"] }
        body = []
        body << %(<p><strong>Meaning:</strong> #{escape(meaning_for("js_endpoints"))}</p>)
        body << %(<p><strong>JS files scanned:</strong> #{escape(data[:js_files_scanned])} | <strong>Potential secret patterns:</strong> #{escape(data[:potential_secrets])}</p>)
        body << section_table_inner(["Source", "Endpoint"], rows.empty? ? [["(none)", "(none)"]] : rows)
        unless Array(data[:findings]).empty?
          cards = Array(data[:findings]).map { |finding| finding_card(symbolize_keys(finding)) }.join
          body << %(<div class="finding-grid">#{cards}</div>)
        end
        %(<details><summary>JavaScript and SPA Endpoints</summary>#{body.join}</details>)
      rescue StandardError
        ""
      end

      def section_knowledge_graph(graph)
        normalized = graph.respond_to?(:to_h) ? graph.to_h : graph
        graph_data = symbolize_keys(normalized || {})
        return "" if graph_data.empty?

        node_rows = Array(graph_data[:nodes]).map { |node| [node[:id], node[:type], JSON.generate(node[:data] || {})] }
        edge_rows = Array(graph_data[:edges]).map { |edge| [edge[:from], edge[:relation], edge[:to]] }
        body = []
        body << %(<p class="muted">The knowledge graph links hosts, IPs, services, findings, and ownership context so pivots remain visible after the scan.</p>)
        body << "<h3>Nodes</h3>"
        body << section_table_inner(["Node", "Type", "Data"], node_rows.empty? ? [["(none)", "(none)", "(none)"]] : node_rows)
        body << "<h3>Edges</h3>"
        body << section_table_inner(["From", "Relation", "To"], edge_rows.empty? ? [["(none)", "(none)", "(none)"]] : edge_rows)
        %(<details><summary>Knowledge Graph</summary>#{body.join}</details>)
      rescue StandardError
        ""
      end

      def section_table(title, explanation, headers, rows, open: false)
        body = []
        body << %(<p class="muted">#{escape(explanation)}</p>)
        if rows.empty?
          body << "<p>No data collected.</p>"
        else
          body << section_table_inner(headers, rows)
        end

        %(<details#{open ? " open" : ""}><summary>#{escape(title)}</summary>#{body.join}</details>)
      rescue StandardError
        ""
      end

      def section_table_inner(headers, rows)
        "<table><thead><tr>#{headers.map { |header| "<th>#{escape(header)}</th>" }.join}</tr></thead><tbody>#{rows.map { |row| "<tr>#{row.map { |value| "<td>#{escape(value)}</td>" }.join}</tr>" }.join}</tbody></table>"
      rescue StandardError
        ""
      end

      def pretty_kv_rows(value)
        normalized = symbolize_keys(value)
        case normalized
        when Array
          normalized.flat_map.with_index do |entry, index|
            if entry.is_a?(Hash)
              entry.map { |key, nested| ["#{index + 1}. #{key}", nested] }
            else
              [["#{index + 1}", entry]]
            end
          end
        when Hash
          normalized.map { |key, nested| [key, nested] }
        else
          [[value.class.name, value]]
        end
      rescue StandardError
        []
      end

      def finding_card(finding)
        severity = finding[:severity].to_s
        %(
          <article class="finding #{escape(severity)}">
            <h3>#{escape(finding[:title])}</h3>
            <p><strong>Severity:</strong> #{escape(severity.upcase)}</p>
            <p><strong>Host:</strong> #{escape(finding[:host])}</p>
            <p><strong>What it means:</strong> #{escape(finding[:description])}</p>
            <p><strong>Recommendation:</strong> #{escape(finding[:remediation])}</p>
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
            <p class="muted">Higher scores usually mean more exposed services, technologies, or correlated signals.</p>
            <div>#{rules}</div>
          </article>
        )
      rescue StandardError
        ""
      end

      def correlation_summary(entry)
        item = symbolize_keys(entry)
        item.reject { |key, _value| key == :type }.map { |key, value| "#{key}=#{value}" }.join(", ")
      rescue StandardError
        ""
      end

      def line_chart_svg(counts)
        values = [
          ["Subdomains", counts[:subdomains].to_i],
          ["IPs", counts[:ips].to_i],
          ["Ports", counts[:open_ports].to_i],
          ["Web", counts[:http_responses].to_i],
          ["Findings", counts[:findings].to_i]
        ]
        max = [values.map(&:last).max.to_i, 1].max
        width = 360.0
        height = 180.0
        step = width / (values.size - 1)
        points = values.each_with_index.map do |(_label, value), index|
          x = 20 + (index * step)
          y = 160 - ((value.to_f / max) * 120)
          "#{x.round(2)},#{y.round(2)}"
        end.join(" ")
        labels = values.each_with_index.map do |(label, _value), index|
          x = 20 + (index * step)
          %(<text x="#{x.round(2)}" y="176" font-size="11" text-anchor="middle" fill="#{ASRFacet::Colors.hex(:muted)}">#{escape(label)}</text>)
        end.join

        %(
          <svg viewBox="0 0 400 190" width="100%" height="220" role="img" aria-label="Exposure line chart">
            <line x1="20" y1="160" x2="380" y2="160" stroke="#{ASRFacet::Colors.hex(:line)}" stroke-width="2" />
            <line x1="20" y1="20" x2="20" y2="160" stroke="#{ASRFacet::Colors.hex(:line)}" stroke-width="2" />
            <polyline fill="none" stroke="#{ASRFacet::Colors.hex(:primary)}" stroke-width="4" points="#{points}" />
            #{labels}
          </svg>
        )
      rescue StandardError
        ""
      end

      def severity_pie_svg(findings)
        counts = severity_counts(findings)
        total = counts.values.sum
        return %(<p class="muted">No findings were available for charting.</p>) if total.zero?

        palette = {
          critical: ASRFacet::Colors.hex(:danger),
          high: ASRFacet::Colors.hex(:high),
          medium: ASRFacet::Colors.hex(:warning),
          low: ASRFacet::Colors.hex(:info),
          info: ASRFacet::Colors.hex(:muted)
        }

        start_angle = 0.0
        slices = counts.map do |severity, value|
          next if value.to_i <= 0

          angle = (value.to_f / total) * 360.0
          path = pie_slice_path(100, 100, 72, start_angle, start_angle + angle)
          start_angle += angle
          %(<path d="#{path}" fill="#{palette[severity] || ASRFacet::Colors.hex(:muted)}"></path>)
        end.compact.join

        %(
          <svg viewBox="0 0 200 200" width="100%" height="220" role="img" aria-label="Finding severity pie chart">
            #{slices}
            <circle cx="100" cy="100" r="34" fill="#{ASRFacet::Colors.hex(:paper)}"></circle>
            <text x="100" y="96" font-size="15" text-anchor="middle" fill="#{ASRFacet::Colors.hex(:ink)}">#{escape(total)}</text>
            <text x="100" y="116" font-size="11" text-anchor="middle" fill="#{ASRFacet::Colors.hex(:muted)}">findings</text>
          </svg>
        )
      rescue StandardError
        ""
      end

      def severity_legend(findings)
        counts = severity_counts(findings)
        palette = {
          critical: ASRFacet::Colors.hex(:danger),
          high: ASRFacet::Colors.hex(:high),
          medium: ASRFacet::Colors.hex(:warning),
          low: ASRFacet::Colors.hex(:info),
          info: ASRFacet::Colors.hex(:muted)
        }
        items = counts.map do |severity, value|
          %(<span><i style="background: #{palette[severity] || ASRFacet::Colors.hex(:muted)}"></i>#{escape(severity.to_s)}: #{escape(value)}</span>)
        end.join
        %(<div class="legend">#{items}</div>)
      rescue StandardError
        ""
      end

      def pie_slice_path(cx, cy, radius, start_angle, end_angle)
        start_rad = Math::PI * start_angle / 180.0
        end_rad = Math::PI * end_angle / 180.0
        x1 = cx + radius * Math.cos(start_rad)
        y1 = cy + radius * Math.sin(start_rad)
        x2 = cx + radius * Math.cos(end_rad)
        y2 = cy + radius * Math.sin(end_rad)
        large_arc = (end_angle - start_angle) > 180 ? 1 : 0
        "M #{cx} #{cy} L #{x1.round(2)} #{y1.round(2)} A #{radius} #{radius} 0 #{large_arc} 1 #{x2.round(2)} #{y2.round(2)} Z"
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
