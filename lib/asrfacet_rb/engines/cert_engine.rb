# Part of ASRFacet-Rb — authorized testing only
require "time"

module ASRFacet
  module Engines
    class CertEngine
      include ASRFacet::Mixins::Network

      def initialize(target = nil, options = {})
        @target = target
        @options = options || {}
      end

      def run(host = @target, port: 443)
        data = analyze_cert(host, port: port)
        {
          engine: "cert_engine",
          target: host.to_s,
          timestamp: Time.now.iso8601,
          status: data.empty? ? :failed : :success,
          data: data,
          errors: data.empty? ? ["Certificate unavailable"] : []
        }
      rescue StandardError => e
        { engine: "cert_engine", target: host.to_s, timestamp: Time.now.iso8601, status: :failed, data: {}, errors: [e.message] }
      end

      def analyze_cert(host, port: 443)
        cert = ssl_cert(host, port: port)
        return {} if cert.nil?

        {
          host: host,
          subject: cert.subject.to_s,
          issuer: cert.issuer.to_s,
          not_before: cert.not_before,
          not_after: cert.not_after,
          expired: cert.not_after < Time.now,
          self_signed: cert.subject.to_s == cert.issuer.to_s,
          sans: extract_sans(cert)
        }
      rescue StandardError
        {}
      end

      def extract_sans(cert)
        extension = cert.extensions.find { |entry| entry.oid == "subjectAltName" }
        return [] unless extension

        extension.value.to_s.split(",").map do |entry|
          entry.to_s.strip.sub(/\ADNS:/, "").sub(/\A\*\./, "")
        end.reject(&:empty?).uniq
      rescue StandardError
        []
      end

      def new_subdomains(sans, target_domain)
        Array(sans).map(&:downcase).select do |hostname|
          hostname == target_domain || hostname.end_with?(".#{target_domain}")
        end.uniq.sort
      rescue StandardError
        []
      end
    end
  end
end
