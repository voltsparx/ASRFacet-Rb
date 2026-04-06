# Part of ASRFacet-Rb — authorized testing only
require "time"

module ASRFacet
  module Engines
    class WhoisEngine
      include ASRFacet::Mixins::Network

      def initialize(target = nil, options = {})
        @target = target
        @options = options || {}
      end

      def run(domain = @target)
        record = whois_lookup(domain)
        parser = record&.parser
        data = {
          registrar: safe_parser_call(parser, :registrar),
          created_on: safe_parser_call(parser, :created_on),
          updated_on: safe_parser_call(parser, :updated_on),
          expires_on: safe_parser_call(parser, :expires_on),
          nameservers: Array(safe_parser_call(parser, :nameservers)).map(&:to_s),
          registrant_org: safe_parser_call(parser, :registrant_organization) || safe_parser_call(parser, :registrant_org)
        }
        {
          engine: "whois_engine",
          target: domain.to_s,
          timestamp: Time.now.iso8601,
          status: data.values.compact.empty? ? :failed : :success,
          data: data,
          errors: []
        }
      rescue StandardError => e
        { engine: "whois_engine", target: domain.to_s, timestamp: Time.now.iso8601, status: :failed, data: {}, errors: [e.message] }
      end

      private

      def safe_parser_call(parser, method_name)
        parser&.public_send(method_name)
      rescue StandardError
        nil
      end
    end
  end
end
