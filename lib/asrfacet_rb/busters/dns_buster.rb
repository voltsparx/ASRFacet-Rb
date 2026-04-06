# Part of ASRFacet-Rb — authorized testing only
require "resolv"
require "securerandom"
require "thread"

module ASRFacet::Busters
  class DnsBuster < BaseBuster
    def initialize(domain, wordlist, workers: 100)
      @domain = domain.to_s.downcase
      @wordlist = wordlist
      @workers = workers.to_i.positive? ? workers.to_i : 100
      @mutex = Mutex.new
      @wildcard_ips = detect_wildcard
    end

    def run
      results = []
      pool = ASRFacet::ThreadPool.new(@workers)

      File.foreach(@wordlist).lazy.each do |line|
        word = line.to_s.strip.downcase
        next if word.empty? || word.start_with?("#")

        pool.enqueue do
          hostname = "#{word}.#{@domain}"
          ips = Resolv.getaddresses(hostname).uniq
          filtered_ips = ips - @wildcard_ips
          next if filtered_ips.empty?

          @mutex.synchronize do
            results << { subdomain: hostname, ips: filtered_ips.sort }
          end
        rescue StandardError
          nil
        end
      end

      pool.wait
      results.uniq.sort_by { |entry| entry[:subdomain] }
    rescue StandardError
      []
    end

    private

    def detect_wildcard
      Resolv.getaddresses("#{SecureRandom.hex(12)}.#{@domain}").uniq
    rescue StandardError
      []
    end
  end
end
