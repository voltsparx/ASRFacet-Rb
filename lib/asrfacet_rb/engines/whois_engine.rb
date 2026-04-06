# Part of ASRFacet-Rb — authorized testing only
module ASRFacet::Engines
  class WhoisEngine
    include ASRFacet::Mixins::Network

    def run(domain)
      record = whois_lookup(domain)
      parser = record&.parser

      {
        registrar: safe_parser_call(parser, :registrar),
        created_on: safe_parser_call(parser, :created_on),
        updated_on: safe_parser_call(parser, :updated_on),
        expires_on: safe_parser_call(parser, :expires_on),
        nameservers: Array(safe_parser_call(parser, :nameservers)).map(&:to_s),
        registrant_org: safe_parser_call(parser, :registrant_organization) || safe_parser_call(parser, :registrant_org)
      }
    rescue StandardError
      {}
    end

    private

    def safe_parser_call(parser, method_name)
      parser&.public_send(method_name)
    rescue StandardError
      nil
    end
  end
end
