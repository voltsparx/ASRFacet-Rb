# Part of ASRFacet-Rb — authorized testing only
require "cgi"
require "json"
require "time"

module ASRFacet
  module Output
    class ChangeTracker
      def initialize(domain)
        @monitor = ASRFacet::Engines::MonitoringEngine.new(domain)
      rescue StandardError
        @monitor = ASRFacet::Engines::MonitoringEngine.new(domain.to_s)
      end

      def generate_diff_report(current_results, format: :cli)
        diff = @monitor.diff(current_results)
        case format.to_sym
        when :json
          format_json(diff)
        when :html
          format_html(diff)
        else
          format_cli(diff)
        end
      rescue StandardError
        ""
      end

      def format_cli(diff)
        data = symbolize_keys(diff)
        [
          color_block("NEW ASSETS", data[:new_subdomains], ASRFacet::Colors.terminal(:success)),
          color_block("REMOVED ASSETS", data[:removed_subdomains], ASRFacet::Colors.terminal(:danger)),
          color_block("NEW FINDINGS", Array(data[:new_findings]).map { |finding| "#{finding[:host]} - #{finding[:title]}" }, ASRFacet::Colors.terminal(:warning)),
          color_block("PORT CHANGES", Array(data[:new_open_ports]).map { |port| "#{port[:host]}:#{port[:port]} (#{port[:service]})" }, ASRFacet::Colors.terminal(:info))
        ].join("\n\n")
      rescue StandardError
        ""
      end

      def format_json(diff)
        JSON.pretty_generate(symbolize_keys(diff).merge(generated_at: Time.now.iso8601))
      rescue StandardError
        JSON.pretty_generate(generated_at: Time.now.iso8601)
      end

      def format_html(diff)
        data = symbolize_keys(diff)
        <<~HTML
          <!doctype html>
          <html lang="en">
          <head>
            <meta charset="utf-8">
            <title>ASRFacet-Rb Change Report</title>
            <style>
              :root { #{ASRFacet::Colors.css_variables} }
              body { font-family: Georgia, serif; background: var(--wash); color: var(--ink); margin: 0; padding: 2rem; }
              section { background: var(--panel); border-radius: 14px; padding: 1rem 1.25rem; margin-bottom: 1rem; box-shadow: 0 8px 24px rgba(34,27,24,0.08); }
              h1, h2 { margin-top: 0; }
              .new { border-left: 6px solid var(--success); }
              .removed { border-left: 6px solid var(--danger); }
              .changed { border-left: 6px solid var(--orange); }
              ul { margin: 0; padding-left: 1.2rem; }
            </style>
          </head>
          <body>
            <h1>ASRFacet-Rb Change Summary</h1>
            #{html_section("NEW ASSETS", data[:new_subdomains], "new")}
            #{html_section("REMOVED ASSETS", data[:removed_subdomains], "removed")}
            #{html_section("NEW FINDINGS", Array(data[:new_findings]).map { |finding| "#{finding[:host]} - #{finding[:title]}" }, "changed")}
            #{html_section("PORT CHANGES", Array(data[:new_open_ports]).map { |port| "#{port[:host]}:#{port[:port]} (#{port[:service]})" }, "changed")}
          </body>
          </html>
        HTML
      rescue StandardError
        "<html><body><p>Unable to render change report.</p></body></html>"
      end

      private

      def color_block(title, lines, color)
        body = Array(lines).empty? ? "(none)" : Array(lines).map(&:to_s).join("\n")
        "#{title.to_s.colorize(color)}\n#{body}"
      rescue StandardError
        ""
      end

      def html_section(title, lines, css_class)
        items = Array(lines)
        body = if items.empty?
                 "<p>(none)</p>"
               else
                 "<ul>#{items.map { |item| "<li>#{CGI.escapeHTML(item.to_s)}</li>" }.join}</ul>"
               end
        %(<section class="#{css_class}"><h2>#{CGI.escapeHTML(title)}</h2>#{body}</section>)
      rescue StandardError
        ""
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
