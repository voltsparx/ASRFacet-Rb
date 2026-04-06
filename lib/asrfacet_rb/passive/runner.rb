# Part of ASRFacet-Rb — authorized testing only
require "set"
require "thread"

module ASRFacet::Passive
  class Runner
    SOURCES = [
      CrtSh,
      HackerTarget,
      Wayback,
      AlienVault,
      Shodan,
      ThreatCrowd,
      BufferOver,
      RapidDNS
    ].freeze

    def initialize(domain, api_keys = {}, options = {})
      @domain = domain.to_s.downcase
      @api_keys = api_keys || {}
      @options = options || {}
      @mutex = Mutex.new
    end

    def run
      subdomains = Set.new
      errors = []

      threads = SOURCES.map do |source_class|
        Thread.new do
          source = source_class.new
          results = source.run(@domain, @api_keys)
          @mutex.synchronize do
            results.each { |hostname| subdomains << hostname }
          end
        rescue StandardError => e
          @mutex.synchronize do
            errors << { source: source_class.name.split("::").last, error: e.message }
          end
        end
      rescue StandardError => e
        @mutex.synchronize do
          errors << { source: source_class.name.split("::").last, error: e.message }
        end
        nil
      end.compact

      threads.each do |thread|
        thread.join
      rescue StandardError
        nil
      end

      {
        subdomains: subdomains.to_a.sort,
        errors: errors,
        source_count: SOURCES.size
      }
    rescue StandardError
      { subdomains: [], errors: [], source_count: SOURCES.size }
    end
  end
end
