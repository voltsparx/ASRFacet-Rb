# Part of ASRFacet-Rb — authorized testing only
require "tempfile"

module ASRFacet
  class Pipeline
    def initialize(target, options = {})
      @target = ASRFacet::Core::Target.new(target)
      @options = options || {}
      @store = ASRFacet::ResultStore.new
    end

    def run
      @store.add(:subdomains, @target.domain)

      stage(1, "Passive enumeration") do
        passive = ASRFacet::Passive::Runner.new(@target.domain, api_keys).run
        passive[:subdomains].each { |subdomain| @store.add(:subdomains, subdomain) }
        passive[:errors].each { |error| @store.add(:errors, error) }
      end

      stage(2, "DNS enumeration") do
        dns_result = ASRFacet::Engines::DnsEngine.new(@target.domain).run
        store_dns_data(@target.domain, dns_result[:data])
      end

      stage(3, "Permutation and brute force") do
        permutations = ASRFacet::Engines::PermutationEngine.new.generate(@target.domain, @store.all(:subdomains))
        permutations.each { |candidate| @store.add(:candidate_subdomains, candidate) }
        wordlist_path = build_buster_wordlist(permutations)
        ASRFacet::Busters::DnsBuster.new(@target.domain, wordlist_path, workers: thread_count(:dns)).run.each do |entry|
          @store.add(:subdomains, entry[:subdomain])
          Array(entry[:ips]).each { |ip| @store.add(:ips, ip) }
        end
      ensure
        cleanup_tempfile(wordlist_path)
      end

      stage(4, "TLS certificate analysis") do
        cert_engine = ASRFacet::Engines::CertEngine.new
        @store.all(:subdomains).each do |host|
          cert = cert_engine.analyze_cert(host)
          next if cert.empty?

          @store.add(:certs, cert)
          cert_engine.new_subdomains(cert[:sans], @target.domain).each { |subdomain| @store.add(:subdomains, subdomain) }
        end
      end

      stage(5, "Port scanning") do
        port_engine = ASRFacet::Engines::PortEngine.new
        @store.all(:ips).each do |ip|
          port_engine.scan(ip, @options[:ports] || "top100", workers: thread_count(:dns)).each do |port_result|
            @store.add(:open_ports, port_result)
          end
        end
      end

      stage(6, "HTTP probing") do
        http_engine = ASRFacet::Engines::HttpEngine.new
        @store.all(:subdomains).each do |host|
          response = http_engine.probe(host)
          @store.add(:http_responses, response) unless response.nil?
        end
      end

      stage(7, "WHOIS and ASN enrichment") do
        whois = ASRFacet::Engines::WhoisEngine.new.run(@target.domain)
        @store.add(:whois, whois[:data]) unless whois[:data].to_h.empty?

        asn_engine = ASRFacet::Engines::AsnEngine.new
        @store.all(:ips).each do |ip|
          asn = asn_engine.run(ip)
          @store.add(:asn, asn[:data].merge(ip: ip)) unless asn[:data].to_h.empty?
        end
      end

      stage(8, "Crawling") do
        crawl_engine = ASRFacet::Engines::CrawlEngine.new
        @store.all(:http_responses).each do |response|
          crawl = crawl_engine.crawl(response[:url], max_depth: crawl_depth, max_pages: crawl_pages)
          @store.add(:crawl, crawl.merge(host: response[:host])) unless crawl[:pages_crawled].empty?
        end
      end

      stage(9, "Vulnerability checks") do
        findings = ASRFacet::Engines::VulnEngine.new(@target, @store.to_h).run
        findings.each { |finding| @store.add(:findings, finding) }
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

    def thread_count(type = :default)
      configured = @options[:threads]
      return configured.to_i if configured.to_i.positive?

      defaults = ASRFacet::Config.fetch("threads") || {}
      fallback = defaults[type.to_s] || defaults["default"]
      fallback.to_i.positive? ? fallback.to_i : 50
    rescue StandardError
      50
    end

    def crawl_depth
      @options[:crawl_depth].to_i.positive? ? @options[:crawl_depth].to_i : 2
    rescue StandardError
      2
    end

    def crawl_pages
      @options[:crawl_pages].to_i.positive? ? @options[:crawl_pages].to_i : 100
    rescue StandardError
      100
    end

    def store_dns_data(host, data)
      data.each do |record_type, values|
        next if %i[wildcard wildcard_ips zone_transfer].include?(record_type)

        Array(values).each do |value|
          @store.add(:dns, { host: host, type: record_type, value: value })
        end
      end
      Array(data[:a]).each { |ip| @store.add(:ips, ip) }
      Array(data[:aaaa]).each { |ip| @store.add(:ips, ip) }
      Array(data[:wildcard_ips]).each { |ip| @store.add(:wildcard_ips, ip) }
    rescue StandardError
      nil
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
