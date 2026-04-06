# Part of ASRFacet-Rb — authorized testing only
require "set"
require "thread"

module ASRFacet
  module Passive
    class Runner
      SOURCES = [
        CrtSh,
        HackerTarget,
        Wayback,
        RapidDNS,
        AlienVault,
        Shodan,
        ThreatCrowd,
        BufferOver
      ].freeze

      def initialize(domain, api_keys = {}, options = {})
        @domain = domain.to_s.downcase
        @api_keys = api_keys || {}
        @options = options || {}
        @results = Set.new
        @errors = []
        @mutex = Mutex.new
      end

      def run
        threads = SOURCES.map do |source_class|
          Thread.new do
            source = source_class.new
            found = source.run(@domain, @api_keys)
            @mutex.synchronize do
              found.each { |entry| @results << entry }
            end
          rescue StandardError => e
            @mutex.synchronize do
              @errors << { source: source_class.name.split("::").last, error: e.message }
            end
          end
        end

        threads.each do |thread|
          thread.join
        rescue StandardError
          nil
        end

        {
          subdomains: @results.to_a.sort,
          errors: @errors,
          source_count: SOURCES.size
        }
      rescue StandardError
        { subdomains: [], errors: [], source_count: SOURCES.size }
      end
    end
  end
end
