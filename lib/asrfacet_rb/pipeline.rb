# Part of ASRFacet-Rb — authorized testing only
require "tempfile"

module ASRFacet
  class Pipeline
    def initialize(target, options = {})
      @target = ASRFacet::Core::Target.new(target)
      @options = options || {}
      @store = ASRFacet::ResultStore.new
      @graph = ASRFacet::Core::KnowledgeGraph.new
      @memory = ASRFacet::Core::ReconMemory.new(@target.domain)
      @scope = build_scope(@target.domain)
      @filter = ASRFacet::Core::NoiseFilter.new
      @js_summary = { js_files_scanned: 0, endpoints_found: [], potential_secrets: 0, findings: [] }
      @correlations = []
      @top_assets = []
      @diff_result = {}
      @probabilistic_subdomains = []
      @resolved_map = Hash.new { |hash, key| hash[key] = [] }
      @graph.add_node(@target.domain, type: :domain, data: { ip: @target.ip })
    rescue StandardError
      @target = ASRFacet::Core::Target.new(target.to_s)
      @options = options || {}
      @store = ASRFacet::ResultStore.new
      @graph = ASRFacet::Core::KnowledgeGraph.new
      @memory = ASRFacet::Core::ReconMemory.new(@target.domain)
      @scope = build_scope(@target.domain)
      @filter = ASRFacet::Core::NoiseFilter.new
      @js_summary = { js_files_scanned: 0, endpoints_found: [], potential_secrets: 0, findings: [] }
      @correlations = []
      @top_assets = []
      @diff_result = {}
      @probabilistic_subdomains = []
      @resolved_map = Hash.new { |hash, key| hash[key] = [] }
    end

    def run
      @store.add(:subdomains, @target.domain)
      @graph.add_node(@target.domain, type: :subdomain, data: { root: true })
      active_subdomains = [@target.domain]

      stage(1, "Passive reconnaissance") do
        passive = ASRFacet::Passive::Runner.new(@target.domain, api_keys).run
        passive[:subdomains].each do |subdomain|
          @store.add(:subdomains, subdomain)
          @graph.add_node(subdomain, type: :subdomain, data: {})
          @graph.add_edge(@target.domain, subdomain, relation: :belongs_to)
        end
        passive[:errors].each { |error| @store.add(:errors, error) }
        active_subdomains = scope_filter(@store.all(:subdomains))
        active_subdomains = skip_known(active_subdomains)
      end

      stage(2, "DNS resolution") do
        dns_engine = ASRFacet::Engines::DnsEngine.new
        scope_filter(@store.all(:subdomains)).each do |host|
          dns_result = dns_engine.run(host)
          store_dns_data(host, dns_result[:data])
          record_failure("dns_engine", dns_result[:errors].join(", ")) if dns_result[:status] == :failed
        rescue StandardError => e
          record_failure("dns_engine", e.message)
        end

        filtered = @filter.filter_subdomains(scope_filter(@store.all(:subdomains)), @resolved_map)
        active_subdomains = filtered.empty? ? scope_filter(@store.all(:subdomains)) : filtered
        active_subdomains = skip_known(active_subdomains)
      end

      stage(3, "Permutation and DNS busting") do
        permutation_engine = ASRFacet::Engines::PermutationEngine.new
        candidates = permutation_engine.generate(@target.domain, @store.all(:subdomains))
        candidates.each { |candidate| @store.add(:candidate_subdomains, candidate) }
        wordlist_path = build_buster_wordlist(candidates)
        ASRFacet::Busters::DnsBuster.new(@target.domain, wordlist_path, workers: thread_count(:dns)).run.each do |entry|
          next unless @scope.in_scope?(entry[:subdomain])

          @store.add(:subdomains, entry[:subdomain])
          @graph.add_node(entry[:subdomain], type: :subdomain, data: {})
          @graph.add_edge(@target.domain, entry[:subdomain], relation: :belongs_to)
          Array(entry[:ips]).each do |ip|
            remember_resolution(entry[:subdomain], ip)
            @store.add(:ips, ip)
            @graph.add_node(ip, type: :ip, data: {})
            @graph.add_edge(entry[:subdomain], ip, relation: :resolves_to)
          end
        end
      ensure
        cleanup_tempfile(wordlist_path)
        active_subdomains = skip_known(scope_filter(@store.all(:subdomains)))
      end

      stage(4, "Certificate analysis") do
        cert_engine = ASRFacet::Engines::CertEngine.new
        active_subdomains.each do |host|
          cert = cert_engine.analyze_cert(host)
          next if cert.empty?

          @store.add(:certs, cert)
          cert_engine.new_subdomains(cert[:sans], @target.domain).each do |subdomain|
            next unless @scope.in_scope?(subdomain)

            @store.add(:subdomains, subdomain)
            @graph.add_node(subdomain, type: :subdomain, data: { source: "certificate_san" })
            @graph.add_edge(@target.domain, subdomain, relation: :belongs_to)
          end
        rescue StandardError => e
          record_failure("cert_engine", e.message)
        end
        active_subdomains = skip_known(scope_filter(@store.all(:subdomains)))
      end

      stage(5, "Port scanning") do
        port_engine = ASRFacet::Engines::PortEngine.new
        @store.all(:ips).uniq.each do |ip|
          next unless @scope.in_scope?(ip)

          port_engine.scan(ip, @options[:ports] || "top100", workers: thread_count(:dns)).each do |port_result|
            @store.add(:open_ports, port_result)
            service_id = "#{ip}:#{port_result[:port]}"
            @graph.add_node(service_id, type: :service, data: port_result)
            @graph.add_edge(ip, service_id, relation: :runs_on)
          end
        rescue StandardError => e
          record_failure("port_engine", e.message)
        end
      end

      stage(6, "HTTP, crawl, JavaScript, and correlation") do
        http_engine = ASRFacet::Engines::HttpEngine.new
        crawl_engine = ASRFacet::Engines::CrawlEngine.new
        js_engine = ASRFacet::Engines::JsEndpointEngine.new
        http_results = []

        active_subdomains.each do |host|
          next unless @scope.in_scope?(host)

          response = http_engine.probe(host)
          next if response.nil?

          crawl = crawl_engine.crawl(response[:url], max_depth: crawl_depth, max_pages: crawl_pages)
          @store.add(:crawl, crawl.merge(host: host)) unless crawl[:pages_crawled].empty?

          js_urls = (Array(crawl[:scripts]) + js_engine.extract_js_urls(response[:body_preview], response[:url])).uniq
          js_result = js_engine.run(response[:url], js_urls)
          merge_js_summary(js_result)

          response[:crawl] = crawl
          response[:js_urls] = js_urls
          response[:js_endpoints] = js_result[:endpoints_found]
          http_results << response
        rescue StandardError => e
          record_failure("http_engine", e.message)
        end

        filtered_http = @filter.filter_http_results(http_results)
        filtered_http.each { |result| @store.add(:http_responses, result) }
        @store.add(:js_endpoints, @js_summary) unless @js_summary[:js_files_scanned].zero? && @js_summary[:endpoints_found].empty?
        @js_summary[:findings].each { |finding| @store.add(:findings, finding) }

        @correlations = ASRFacet::Engines::CorrelationEngine.new.run(@store.to_h, @graph)
        @correlations.each { |entry| @store.add(:correlations, entry) }
        @top_assets = ASRFacet::Engines::AssetScorer.new.score_all(@store.to_h)
        @top_assets.each { |asset| @store.add(:top_assets, asset) }
      end

      stage(7, "WHOIS and ASN enrichment") do
        whois_result = ASRFacet::Engines::WhoisEngine.new.run(@target.domain)
        @store.add(:whois, whois_result[:data]) unless whois_result[:data].to_h.empty?

        asn_engine = ASRFacet::Engines::AsnEngine.new
        @store.all(:ips).uniq.each do |ip|
          asn_result = asn_engine.run(ip)
          next if asn_result[:data].to_h.empty?

          data = asn_result[:data].merge(ip: ip)
          @store.add(:asn, data)
          asn_id = data[:asn].to_s.empty? ? "asn:#{ip}" : data[:asn].to_s
          @graph.add_node(asn_id, type: :asn, data: data)
          @graph.add_edge(ip, asn_id, relation: :belongs_to)
        rescue StandardError => e
          record_failure("asn_engine", e.message)
        end
      end

      stage(8, "Vulnerability detection and monitoring") do
        vuln_engine = ASRFacet::Engines::VulnEngine.new(@target, @store.to_h)
        findings = @filter.filter_findings(vuln_engine.run)
        findings.each do |finding|
          @store.add(:findings, finding)
          finding_id = "#{finding[:host]}:#{finding[:title]}"
          @graph.add_node(finding_id, type: :finding, data: finding)
          @graph.add_edge(finding[:host], finding_id, relation: :found_by)
        end

        current_results = @store.to_h
        @diff_result = ASRFacet::Engines::MonitoringEngine.new(@target.domain).diff(current_results)
        @probabilistic_subdomains = ASRFacet::Engines::ProbabilisticSubdomainEngine.new(@target.domain, @store.all(:subdomains)).top_candidates
        @probabilistic_subdomains.each { |entry| @store.add(:probabilistic_subdomains, entry) }
        @memory.record_scan(current_results)
      end

      {
        store: @store,
        graph: @graph,
        diff: @diff_result,
        top_assets: @top_assets,
        js_endpoints: @js_summary,
        correlations: @correlations,
        probabilistic_subdomains: @probabilistic_subdomains
      }
    rescue StandardError => e
      record_failure("pipeline", e.message)
      {
        store: @store,
        graph: @graph,
        diff: @diff_result,
        top_assets: @top_assets,
        js_endpoints: @js_summary,
        correlations: @correlations,
        probabilistic_subdomains: @probabilistic_subdomains
      }
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
          next unless %i[a aaaa].include?(record_type)

          remember_resolution(host, value)
          @store.add(:ips, value)
          @graph.add_node(value, type: :ip, data: {})
          @graph.add_edge(host, value, relation: :resolves_to)
        end
      end
      Array(data[:wildcard_ips]).each { |ip| @store.add(:wildcard_ips, ip) }
    rescue StandardError
      nil
    end

    def remember_resolution(host, ip)
      @resolved_map[host.to_s.downcase] << ip.to_s
      @resolved_map[host.to_s.downcase].uniq!
    rescue StandardError
      nil
    end

    def build_buster_wordlist(candidates)
      tempfile = Tempfile.new(["asrfacet-dns-buster", ".txt"])
      Array(candidates).each do |hostname|
        tempfile.write("#{hostname.sub(/\.#{Regexp.escape(@target.domain)}\z/, "")}\n")
      end

      extra_wordlist = @options[:wordlist]
      if extra_wordlist && File.file?(extra_wordlist)
        File.foreach(extra_wordlist).lazy.each { |line| tempfile.write(line) }
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
    rescue StandardError => e
      record_failure(name, e.message)
      nil
    end

    def build_scope(target_domain)
      allowed = split_csv(@options[:scope])
      allowed << target_domain
      excluded = split_csv(@options[:exclude])
      allowed_domains, allowed_ips = partition_targets(allowed)
      excluded_domains, excluded_ips = partition_targets(excluded)
      ASRFacet::Core::ScopeEngine.new(
        allowed_domains: allowed_domains,
        allowed_ips: allowed_ips,
        excluded_domains: excluded_domains,
        excluded_ips: excluded_ips
      )
    rescue StandardError
      ASRFacet::Core::ScopeEngine.new(allowed_domains: [target_domain])
    end

    def split_csv(value)
      value.to_s.split(",").map(&:strip).reject(&:empty?)
    rescue StandardError
      []
    end

    def partition_targets(values)
      domains = []
      ips = []
      Array(values).each do |value|
        if value.match?(/\A\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?\z/)
          ips << value
        else
          domains << value.downcase
        end
      end
      [domains, ips]
    rescue StandardError
      [[], []]
    end

    def scope_filter(targets)
      @scope.filter(Array(targets).uniq)
    rescue StandardError
      Array(targets).uniq
    end

    def skip_known(subdomains)
      return Array(subdomains) unless @options[:memory]

      Array(subdomains).reject { |subdomain| @memory.known?(subdomain) }
    rescue StandardError
      Array(subdomains)
    end

    def merge_js_summary(result)
      @js_summary[:js_files_scanned] += result[:js_files_scanned].to_i
      @js_summary[:potential_secrets] += result[:potential_secrets].to_i
      @js_summary[:endpoints_found] = ((@js_summary[:endpoints_found] || []) + Array(result[:endpoints_found])).uniq.sort
      @js_summary[:findings] = ((@js_summary[:findings] || []) + Array(result[:findings])).uniq
    rescue StandardError
      nil
    end

    def record_failure(engine_name, reason)
      @memory.record_failure(engine_name, reason)
      @store.add(:errors, { engine: engine_name, reason: reason })
    rescue StandardError
      nil
    end
  end
end
