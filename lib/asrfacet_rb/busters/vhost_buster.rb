# Part of ASRFacet-Rb — authorized testing only
require "securerandom"
require "thread"

module ASRFacet::Busters
  class VhostBuster < BaseBuster
    def initialize(domain, base_url: nil, wordlist:, workers: 40)
      @domain = domain.to_s.downcase
      @base_url = base_url || "http://#{@domain}"
      @wordlist = wordlist
      @workers = workers.to_i.positive? ? workers.to_i : 40
      @client = ASRFacet::HTTP::RetryableClient.new
      @mutex = Mutex.new
    end

    def run
      baseline = probe_baseline
      results = []
      pool = ASRFacet::ThreadPool.new(@workers)

      File.foreach(@wordlist).lazy.each do |line|
        word = line.to_s.strip.downcase
        next if word.empty? || word.start_with?("#")

        pool.enqueue do
          vhost = "#{word}.#{@domain}"
          response = @client.get(@base_url, headers: { "Host" => vhost })
          next if response.nil?

          size = response.body.to_s.bytesize
          status = response.code.to_i
          next unless status != baseline[:status] || (size - baseline[:size]).abs > 50

          @mutex.synchronize do
            results << { vhost: vhost, status: status, size: size }
          end
        rescue StandardError
          nil
        end
      end

      pool.wait
      results.uniq.sort_by { |entry| entry[:vhost] }
    rescue StandardError
      []
    end

    private

    def probe_baseline
      random_host = "#{SecureRandom.hex(8)}.#{@domain}"
      response = @client.get(@base_url, headers: { "Host" => random_host })
      { status: response&.code.to_i, size: response&.body.to_s.bytesize }
    rescue StandardError
      { status: 0, size: 0 }
    end
  end
end
