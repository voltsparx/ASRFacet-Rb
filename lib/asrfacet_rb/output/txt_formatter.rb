# Part of ASRFacet-Rb — authorized testing only
require "json"

module ASRFacet
  module Output
    class TxtFormatter < BaseFormatter
      def format(results)
        payload = payload_for(results)
        store = payload[:store]

        sections = []
        sections << render_section("Subdomains", Array(store[:subdomains]))
        sections << render_section("Open Ports", Array(store[:open_ports]).map { |entry| "#{entry[:host]}:#{entry[:port]} #{entry[:service]}" })
        sections << render_section("Technologies", Array(store[:http_responses]).flat_map { |entry| Array(entry[:technologies]).map { |tech| "#{entry[:host]} -> #{tech}" } })
        sections << render_section("Findings", Array(store[:findings]).map { |finding| "#{finding[:severity].to_s.upcase}: #{finding[:host]} - #{finding[:title]}" })
        sections << render_section("Diff", JSON.pretty_generate(payload[:diff] || {})) if payload[:diff]
        sections.compact.join("\n\n")
      rescue StandardError
        ""
      end

      private

      def render_section(title, lines)
        values = lines.is_a?(String) ? lines : Array(lines).map(&:to_s).join("\n")
        return nil if values.to_s.strip.empty?

        "#{title}\n#{values}"
      rescue StandardError
        nil
      end
    end
  end
end
