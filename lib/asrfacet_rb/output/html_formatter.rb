# Part of ASRFacet-Rb — authorized testing only
require "cgi"
require "json"
require "time"

module ASRFacet::Output
  class HtmlFormatter < BaseFormatter
    def format(results)
      data = results.to_h
      generated_at = Time.now.iso8601

      <<~HTML
        <!doctype html>
        <html lang="en">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <title>ASRFacet-Rb Report</title>
          <style>
            body { margin: 0; font-family: Georgia, "Times New Roman", serif; background: linear-gradient(180deg, #f4efe6 0%, #faf8f4 100%); color: #1f1a17; }
            header { padding: 2rem; background: #1f3a5f; color: #fff7e8; }
            header h1 { margin: 0 0 0.5rem; font-size: 2rem; letter-spacing: 0.04em; }
            main { max-width: 1100px; margin: 0 auto; padding: 1.5rem; }
            details { background: rgba(255,255,255,0.88); border: 1px solid #d8cbb6; border-radius: 14px; padding: 1rem 1.25rem; margin-bottom: 1rem; box-shadow: 0 10px 30px rgba(31,26,23,0.08); }
            summary { cursor: pointer; font-weight: 700; }
            table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
            th, td { text-align: left; padding: 0.65rem; border-bottom: 1px solid #e7dbc7; vertical-align: top; }
            th { background: #f5ecdf; }
            .finding-grid { display: grid; gap: 1rem; margin-top: 1rem; }
            .finding { border-left: 6px solid #6c757d; padding: 1rem; border-radius: 12px; background: #fff; }
            .finding.critical { border-color: #a2201a; }
            .finding.high { border-color: #d9480f; }
            .finding.medium { border-color: #d4a017; }
            .finding.low { border-color: #1d4ed8; }
            .finding.info { border-color: #6b7280; }
            .meta { color: #5d5248; font-size: 0.95rem; }
            footer { text-align: center; padding: 1.5rem; color: #5d5248; }
            button.toggle-all { margin-top: 1rem; background: #fff7e8; border: 1px solid #e7dbc7; border-radius: 999px; padding: 0.55rem 1rem; cursor: pointer; }
            code { font-family: Consolas, monospace; background: #f5ecdf; padding: 0.1rem 0.3rem; border-radius: 4px; }
          </style>
        </head>
        <body>
          <header>
            <h1>ASRFacet-Rb Report</h1>
            <div class="meta">Authorized testing output for #{escape(data[:subdomains]&.first || "target")}</div>
            <button class="toggle-all" type="button" onclick="toggleSections()">Toggle Sections</button>
          </header>
          <main>
            #{section_table("Subdomains", ["Host"], Array(data[:subdomains]).sort.map { |host| [host] }, open: true)}
            #{section_table("Open Ports", ["Host", "Port", "Service", "Banner"], Array(data[:open_ports]).sort_by { |entry| [entry[:host].to_s, entry[:port].to_i] }.map { |entry| [entry[:host], entry[:port], entry[:service], entry[:banner]] })}
            #{section_table("Technologies", ["Host", "Technology", "CDN"], Array(data[:http_responses]).flat_map { |entry| Array(entry[:technologies]).map { |tech| [entry[:host], tech, entry[:cdn]] } })}
            #{section_findings(Array(data[:findings]))}
            #{section_pretty("DNS", data[:dns])}
            #{section_pretty("Certificates", data[:certs])}
            #{section_pretty("WHOIS", data[:whois])}
            #{section_pretty("ASN", data[:asn])}
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

      %( <details#{open ? " open" : ""}><summary>#{escape(title)}</summary>#{body}</details> )
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

    def section_pretty(title, data)
      formatted = JSON.pretty_generate(data || [])
      %(<details><summary>#{escape(title)}</summary><pre><code>#{escape(formatted)}</code></pre></details>)
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
