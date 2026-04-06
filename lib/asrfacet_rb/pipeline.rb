# Part of ASRFacet-Rb — authorized testing only
require "tempfile"
require "thread"

module ASRFacet
  class Pipeline
    def initialize(target, options = {})
      @target = ASRFacet::Core::Target.new(target)
      @options = options || {}
      @store = ASRFacet::ResultStore.new
    end

    def run
      stage(1, "Passive enumeration") do
        passive = ASRFacet::Passive::Runner.new(@target.domain, api_keys).run
        @store.add(:subdomains, @target.domain)
        passive[:subdomains].each { |subdomain| @store.add(:subdomains, subdomain) }
        passive[:errors].each { |error| @store.add(:passive_errors, error) }
      end

      stage(2, "DNS enumeration") do
        dns = ASRFacet::Engines::DnsEngine.new.run(@target.domain)
        dns.each do |record_type, values|
          Array(values).each do |value|
            @store.add(:dns, { host: @target.domain, type: record_type, value: value })
          end
        end
        Array(dns[:a]).each { |ip| @store.add(:ips, ip) }
        Array(dns[:aaaa]).each { |ip| @store.add(:ips, ip) }
      end

      stage(3, "Permutation and DNS brute force") do
        known_subdomains = @store.all(:subdomains)
        permutations = ASRFacet::Engines::PermutationEngine.new.generate(@target.domain, known_subdomains)
        wordlist_path = build_buster_wordlist(permutations)
        buster_results = ASRFacet::Busters::DnsBuster.new(@target.domain, wordlist_path, workers: thread_count).run
        permutations.each { |candidate| @store.add(:candidate_subdomains, candidate) }
        buster_results.each do |entry|
          @store.add(:subdomains, entry[:subdomain])
          entry[:ips].each { |ip| @store.add(:ips, ip) }
        end
      ensure
        cleanup_tempfile(wordlist_path)
      end

      stage(4, "Certificate analysis") do
        cert_engine = ASRFacet::Engines::CertEngine.new
        @store.all(:subdomains).each do |host|
          cert = cert_engine.analyze_cert(host)
          next if cert.empty?

          @store.add(:certs, cert)
          cert_engine.new_subdomains(cert[:sans], @target.domain).each do |subdomain|
            @store.add(:subdomains, subdomain)
          end
        end
      end

      stage(5, "Port scanning") do
        port_engine = ASRFacet::Engines::PortEngine.new
        @store.all(:ips).each do |ip|
          port_engine.scan(ip, @options[:ports] || "top100", workers: thread_count).each do |port_result|
            @store.add(:open_ports, port_result)
          end
        end
      end

      stage(6, "HTTP probing") do
        engine = ASRFacet::Engines::HttpEngine.new
        mutex = Mutex.new
        responses = []
        pool = ASRFacet::ThreadPool.new([thread_count / 2, 1].max)

        @store.all(:subdomains).each do |host|
          pool.enqueue do
            result = engine.probe(host)
            next if result.nil?

            mutex.synchronize { responses << result }
          rescue StandardError
            nil
          end
        end

        pool.wait
        responses.each { |result| @store.add(:http_responses, result) }
      end

      stage(7, "WHOIS and ASN enrichment") do
        whois = ASRFacet::Engines::WhoisEngine.new.run(@target.domain)
        @store.add(:whois, whois) unless whois.empty?

        asn_engine = ASRFacet::Engines::AsnEngine.new
        @store.all(:ips).each do |ip|
          asn = asn_engine.run(ip)
          @store.add(:asn, asn.merge(ip: ip)) unless asn.empty?
        end
      end

      stage(8, "Vulnerability checks") do
        vuln_results = ASRFacet::Engines::VulnEngine.new(
          @target,
          http_results: @store.all(:http_responses),
          cert_results: @store.all(:certs)
        ).run
        vuln_results.each { |finding| @store.add(:findings, finding) }
      end

      @store
    rescue StandardError
      @store
    end

    private

    def api_keys
      @options.fetch(:api_keys, {})
    rescue StandardError
      {}
    end

    def thread_count
      value = @options[:threads].to_i
      value.positive? ? value : 100
    rescue StandardError
      100
    end

    def build_buster_wordlist(permutations)
      tempfile = Tempfile.new(["asrfacet-dns-buster", ".txt"])
      permutations.each do |hostname|
        tempfile.write("#{hostname.sub(/\.#{Regexp.escape(@target.domain)}\z/, "")}\n")
      end

      extra_wordlist = @options[:wordlist]
      if extra_wordlist && File.file?(extra_wordlist)
        File.foreach(extra_wordlist).lazy.each do |line|
          tempfile.write(line)
        end
      end

      tempfile.flush
      tempfile.close
      tempfile.path
    rescue StandardError
      @options[:wordlist]
    end

    def cleanup_tempfile(path)
      return if path.to_s.empty?
      return unless File.basename(path.to_s).start_with?("asrfacet-dns-buster")

      File.delete(path) if File.exist?(path)
    rescue StandardError
      nil
    end

    def stage(index, name)
      @options[:stage_callback]&.call(index, name)
      yield
    rescue StandardError
      nil
    end
  end
end
