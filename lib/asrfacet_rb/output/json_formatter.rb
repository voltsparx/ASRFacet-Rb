# Part of ASRFacet-Rb — authorized testing only
require "json"
require "time"

module ASRFacet::Output
  class JsonFormatter < BaseFormatter
    def format(results)
      payload = payload_for(results)
      JSON.pretty_generate(payload[:store].merge(
                             graph: payload[:graph].respond_to?(:to_h) ? payload[:graph].to_h : payload[:graph],
                             diff: payload[:diff],
                             top_assets: payload[:top_assets],
                             js_endpoints: payload[:js_endpoints],
                             correlations: payload[:correlations],
                             probabilistic_subdomains: payload[:probabilistic_subdomains],
                             generated_at: Time.now.iso8601
                           ).compact)
    rescue StandardError
      JSON.pretty_generate(generated_at: Time.now.iso8601)
    end
  end
end
