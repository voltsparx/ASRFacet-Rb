# Part of ASRFacet-Rb — authorized testing only
require "json"
require "time"

module ASRFacet::Output
  class JsonFormatter < BaseFormatter
    def format(results)
      JSON.pretty_generate(results.to_h.merge(generated_at: Time.now.iso8601))
    rescue StandardError
      JSON.pretty_generate(generated_at: Time.now.iso8601)
    end
  end
end
