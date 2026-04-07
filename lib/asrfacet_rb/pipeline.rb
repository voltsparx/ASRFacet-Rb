# SPDX-License-Identifier: Proprietary
#
# ASRFacet-Rb: Attack Surface Reconnaissance Framework
# Copyright (c) 2026 voltsparx
#
# Author: voltsparx
# Repository: https://github.com/voltsparx/ASRFacet-Rb
# Contact: voltsparx@gmail.com
# License: See LICENSE file in the project root
#
# This file is part of ASRFacet-Rb and is subject to the terms
# and conditions defined in the LICENSE file.

require "set"
require "tempfile"
require "uri"

module ASRFacet
  class Pipeline
    def initialize(target, options = {})
      @target = ASRFacet::Core::Target.new(target)
      @options = options || {}
      @config = ASRFacet::Config.load
      @store = ASRFacet::ResultStore.new
      @event_bus = ASRFacet::EventBus.new
      @bus = @event_bus
      @graph = ASRFacet::Core::KnowledgeGraph.new
      @memory = ASRFacet::Core::ReconMemory.new(@target.domain)
      @scope = build_scope(@target.domain)
      @filter = ASRFacet::Core::NoiseFilter.new
      @rate_controller = build_rate_controller
      @http_client = build_http_client
      @notifier = ASRFacet::Notifiers::WebhookNotifier.new(
        @options[:webhook_url],
        platform: (@options[:webhook_platform] || :slack).to_sym
      )
      @js_summary = { js_files_scanned: 0, endpoints_found: [], potential_secrets: 0, findings: [] }
      @correlations = []
      @top_assets = []
      @diff_result = {}
      @change_summary = ""
      @probabilistic_subdomains = []
      @resolved_map = Hash.new { |hash, key| hash[key] = [] }
      @pending_subdomains = []
      @queued_subdomains = Set.new
      @processed_discovery_hosts = Set.new
      @processed_port_ips = Set.new
      @processed_http_hosts = Set.new
      @processed_headless_hosts = Set.new
      @processed_asn_ips = Set.new
      @circuit_breakers = Hash.new { |hash, key| hash[key] = build_circuit_breaker(key) }
      @streamer = build_streamer
      setup_event_subscribers
      emit(:domain, { id: @target.domain, ip: @target.ip })
    rescue StandardError
      @target = ASRFacet::Core::Target.new(target.to_s)
      @options = options || {}
      @config = ASRFacet::Config.load
      @store = ASRFacet::ResultStore.new
      @event_bus = ASRFacet::EventBus.new
      @bus = @event_bus
      @graph = ASRFacet::Core::KnowledgeGraph.new
      @memory = ASRFacet::Core::ReconMemory.new(@target.domain)
      @scope = build_scope(@target.domain)
      @filter = ASRFacet::Core::NoiseFilter.new
      @rate_controller = build_rate_controller
      @http_client = build_http_client
      @notifier = ASRFacet::Notifiers::WebhookNotifier.new(
        @options[:webhook_url],
        platform: (@options[:webhook_platform] || :slack).to_sym
      )
      @js_summary = { js_files_scanned: 0, endpoints_found: [], potential_secrets: 0, findings: [] }
      @correlations = []
      @top_assets = []
      @diff_result = {}
      @change_summary = ""
      @probabilistic_subdomains = []
      @resolved_map = Hash.new { |hash, key| hash[key] = [] }
      @pending_subdomains = []
      @queued_subdomains = Set.new
      @processed_discovery_hosts = Set.new
      @processed_port_ips = Set.new
      @processed_http_hosts = Set.new
      @processed_headless_hosts = Set.new
      @processed_asn_ips = Set.new
      @circuit_breakers = Hash.new { |hash, key| hash[key] = build_circuit_breaker(key) }
      @streamer = build_streamer
      setup_event_subscribers
    end

    def run
      @streamer&.write("scan_started", { target: @target.domain, options: @options })
      emit(:subdomain, { host: @target.domain, parent: @target.domain, data: { root: true } })

      stage(1, "Passive reconnaissance") do
        passive_runner = build_component(ASRFacet::Passive::Runner, @target.domain, api_keys)
        passive = with_circuit("passive_runner") { passive_runner.run } || { subdomains: [], errors: [] }
        passive[:subdomains].each do |subdomain|
          next unless @scope.in_scope?(subdomain)

          emit(:subdomain, { host: subdomain, parent: @target.domain })
        end
        passive[:errors].each { |error| emit(:error, { engine: "passive_runner", reason: error }) }
      end

      stage(2, "Recursive DNS and certificate discovery") do
        with_circuit("recursive_discovery") { drain_subdomain_discovery_queue }
      end

      stage(3, "Permutation and DNS busting") do
        permutation_engine = ASRFacet::Engines::PermutationEngine.new
        candidates = permutation_engine.generate(@target.domain, @store.all(:subdomains))
        candidates.each { |candidate| @store.add(:candidate_subdomains, candidate) }
        wordlist_path = build_buster_wordlist(candidates)
        ASRFacet::Busters::DnsBuster.new(@target.domain, wordlist_path, workers: thread_count(:dns)).run.each do |entry|
          next unless @scope.in_scope?(entry[:subdomain])

          emit(:subdomain, { host: entry[:subdomain], parent: @target.domain, data: { source: "dns_buster" } })
          Array(entry[:ips]).each do |ip|
            next unless @scope.in_scope?(ip)

            emit(:dns_record, { host: entry[:subdomain], type: :a, value: ip })
          end
        end
      ensure
        cleanup_tempfile(wordlist_path)
      end

      stage(4, "Discovery feedback loop") do
        with_circuit("recursive_discovery") { drain_subdomain_discovery_queue }
      end

      stage(5, "Port scanning") do
        with_circuit("port_engine") { process_pending_ports }
      end

      stage(6, "HTTP, crawl, JavaScript, and correlation") do
        with_circuit("http_engine") { process_pending_http }
        process_headless_results if @options[:headless]
        @correlations = with_circuit("correlation_engine") { build_component(ASRFacet::Engines::CorrelationEngine).run(@store.to_h, @graph) } || []
        @correlations.each { |entry| emit(:correlation, entry) }
        @top_assets = with_circuit("asset_scorer") { build_component(ASRFacet::Engines::AssetScorer).score_all(@store.to_h) } || []
        @top_assets.each { |asset| @store.add(:top_assets, asset) }
      end

      stage(7, "WHOIS and ASN enrichment") do
        whois_result = with_circuit("whois_engine") { build_component(ASRFacet::Engines::WhoisEngine).run(@target.domain) } || { data: {} }
        @store.add(:whois, whois_result[:data]) unless whois_result[:data].to_h.empty?
        with_circuit("asn_engine") { process_pending_asn }
      end

      stage(8, "Vulnerability detection and monitoring") do
        vuln_engine = build_component(ASRFacet::Engines::VulnEngine, @target, @store.to_h)
        findings = @filter.filter_findings(with_circuit("vuln_engine") { vuln_engine.run } || [])
        findings.each do |finding|
          emit(:finding, finding)
          @notifier.notify_finding(finding)
        end

        current_results = @store.to_h
        monitoring_engine = build_component(ASRFacet::Engines::MonitoringEngine, @target.domain)
        @diff_result = with_circuit("monitoring_engine") { monitoring_engine.diff(current_results) } || {}
        @change_summary = monitoring_engine.respond_to?(:report_diff) ? monitoring_engine.report_diff(@diff_result).to_s : ""
        unless @change_summary.empty?
          @store.add(:change_summaries, { target: @target.domain, summary: @change_summary, changed_at: Time.now.iso8601 })
          @streamer&.write("change_summary", { target: @target.domain, summary: @change_summary, diff: @diff_result })
        end

        @probabilistic_subdomains = with_circuit("probabilistic_subdomain_engine") do
          build_component(ASRFacet::Engines::ProbabilisticSubdomainEngine, @target.domain, @store.all(:subdomains)).top_candidates
        end || []
        @probabilistic_subdomains.each { |entry| @store.add(:probabilistic_subdomains, entry) }
        @memory.record_scan(current_results)
      end

      result = build_result
      @notifier.notify_scan_complete(@store)
      @streamer&.write("scan_completed", result)
      result
    rescue StandardError => e
      record_failure("pipeline", e.message)
      result = build_result
      @streamer&.write("scan_failed", result.merge(error: e.message))
      result
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
          next if %i[a aaaa].include?(record_type.to_sym) && !@scope.in_scope?(value)

          emit(:dns_record, { host: host, type: record_type, value: value })
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
      @options[:stage_callback]&.call(index, name, :start, build_stage_snapshot(index, name))
      result = yield
      @options[:stage_callback]&.call(index, name, :complete, build_stage_snapshot(index, name))
      result
    rescue StandardError => e
      record_failure(name, e.message)
      nil
    end

    def build_scope(target_domain)
      allowed = split_csv(@options[:scope])
      allowed << target_domain
      allowed << "*.#{target_domain}"
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

    def merge_js_summary(result)
      @js_summary[:js_files_scanned] += result[:js_files_scanned].to_i
      @js_summary[:potential_secrets] += result[:potential_secrets].to_i
      @js_summary[:endpoints_found] = ((@js_summary[:endpoints_found] || []) + Array(result[:endpoints_found])).uniq.sort
      @js_summary[:findings] = ((@js_summary[:findings] || []) + Array(result[:findings])).uniq
    rescue StandardError
      nil
    end

    def record_failure(engine_name, reason)
      @circuit_breakers[engine_name.to_s].record_failure
      @memory.record_failure(engine_name, reason)
      @streamer&.write("failure", { engine: engine_name, reason: reason, breaker: @circuit_breakers[engine_name.to_s].state })
      emit(:error, { engine: engine_name, reason: reason })
    rescue StandardError
      nil
    end

    def enqueue_subdomain(host)
      name = host.to_s.downcase
      return if name.empty?
      return unless @scope.in_scope?(name)
      return if @processed_discovery_hosts.include?(name)
      return if @queued_subdomains.include?(name)
      return if @options[:memory] && name != @target.domain && @memory.known?(name)

      @pending_subdomains << name
      @queued_subdomains << name
    rescue StandardError
      nil
    end

    def drain_subdomain_discovery_queue
      dns_engine = build_component(ASRFacet::Engines::DnsEngine)
      cert_engine = build_component(ASRFacet::Engines::CertEngine)

      until @pending_subdomains.empty?
        begin
          host = @pending_subdomains.shift
          @queued_subdomains.delete(host)
          next unless @scope.in_scope?(host)
          next if @processed_discovery_hosts.include?(host)

          dns_result = dns_engine.run(host)
          store_dns_data(host, dns_result[:data])
          record_failure("dns_engine", dns_result[:errors].join(", ")) if dns_result[:status] == :failed

          cert = cert_engine.analyze_cert(host)
          unless cert.empty?
            emit(:ssl_cert, cert)
            cert_engine.new_subdomains(cert[:sans], @target.domain).each do |subdomain|
              emit(:subdomain, { host: subdomain, parent: @target.domain, data: { source: "certificate_san" } }) if @scope.in_scope?(subdomain)
            end
          end

          @processed_discovery_hosts << host
        rescue StandardError => e
          record_failure("recursive_discovery", "#{host}: #{e.message}")
        end
      end
    rescue StandardError => e
      record_failure("recursive_discovery", e.message)
    end

    def process_pending_ports
      port_engine = build_component(ASRFacet::Engines::PortEngine)
      scope_filter(@store.all(:ips).uniq).each do |ip|
        next if @processed_port_ips.include?(ip)
        next unless @scope.in_scope?(ip)

        port_engine.scan(ip, @options[:ports] || "top100", workers: thread_count(:dns)).each do |port_result|
          emit(:open_port, port_result.merge(host: ip))
        end
        @processed_port_ips << ip
      rescue StandardError => e
        record_failure("port_engine", "#{ip}: #{e.message}")
      end
    rescue StandardError => e
      record_failure("port_engine", e.message)
    end

    def process_pending_http
      http_engine = build_component(ASRFacet::Engines::HttpEngine)
      crawl_engine = build_component(ASRFacet::Engines::CrawlEngine)
      js_engine = build_component(ASRFacet::Engines::JsEndpointEngine)
      http_results = []

      scope_filter(@resolved_map.keys).each do |host|
        next if @processed_http_hosts.include?(host)
        next unless @scope.in_scope?(host)

        response = http_engine.probe(host)
        @processed_http_hosts << host
        next if response.nil?

        crawl = crawl_engine.crawl(response[:url], max_depth: crawl_depth, max_pages: crawl_pages)
        emit(:crawl, crawl.merge(host: host)) unless crawl[:pages_crawled].empty?

        js_urls = (Array(crawl[:scripts]) + js_engine.extract_js_urls(response[:body_preview], response[:url])).uniq
        js_result = js_engine.run(response[:url], js_urls)
        merge_js_summary(js_result)

        response[:crawl] = crawl
        response[:js_urls] = js_urls
        response[:js_endpoints] = js_result[:endpoints_found]
        http_results << response
      rescue StandardError => e
        @processed_http_hosts << host unless host.to_s.empty?
        record_failure("http_engine", "#{host}: #{e.message}")
      end

      filtered_http = @filter.filter_http_results(http_results)
      filtered_http.each { |result| emit(:http_response, result) }
      emit(:js_endpoint, @js_summary) unless @js_summary[:js_files_scanned].zero? && @js_summary[:endpoints_found].empty?
      @js_summary[:findings].each { |finding| emit(:finding, finding) }
    rescue StandardError => e
      record_failure("http_engine", e.message)
    end

    def process_pending_asn
      asn_engine = build_component(ASRFacet::Engines::AsnEngine)
      scope_filter(@store.all(:ips).uniq).each do |ip|
        next if @processed_asn_ips.include?(ip)
        next unless @scope.in_scope?(ip)

        asn_result = asn_engine.run(ip)
        @processed_asn_ips << ip
        next if asn_result[:data].to_h.empty?

        emit(:asn, asn_result[:data].merge(ip: ip))
      rescue StandardError => e
        @processed_asn_ips << ip unless ip.to_s.empty?
        record_failure("asn_engine", "#{ip}: #{e.message}")
      end
    rescue StandardError => e
      record_failure("asn_engine", e.message)
    end

    def emit(event_type, data)
      @streamer&.write("event", { type: event_type, data: data })
      @options[:event_callback]&.call(event_type, symbolize_keys(data))
      @event_bus.emit(event_type, data, dispatch_now: true)
    rescue StandardError
      nil
    end

    def with_circuit(engine_name)
      breaker = @circuit_breakers[engine_name.to_s]
      unless breaker.allow?
        reason = "Circuit open for #{engine_name}; skipping until cooldown expires"
        emit(:error, { engine: engine_name, reason: reason })
        @streamer&.write("circuit_open", { engine: engine_name, breaker: breaker.state })
        return nil
      end

      result = yield
      breaker.record_success
      result
    rescue StandardError => e
      breaker.record_failure
      @streamer&.write("circuit_failure", { engine: engine_name, reason: e.message, breaker: breaker.state })
      raise e
    end

    def build_circuit_breaker(name = nil)
      config = ASRFacet::Config.fetch("resilience", "circuit_breaker") || {}
      ASRFacet::Core::CircuitBreaker.new(
        name,
        failure_threshold: config["threshold"] || 3,
        cooldown_seconds: config["cooldown"] || 60
      )
    rescue StandardError
      ASRFacet::Core::CircuitBreaker.new(name)
    end

    def build_streamer
      output_directory = resolve_output_directory
      ASRFacet::Output::JsonlStream.new(@target.domain, base_dir: File.join(output_directory, "streams"))
    rescue StandardError
      nil
    end

    def resolve_output_directory
      File.expand_path((ASRFacet::Config.fetch("output", "directory") || "~/.asrfacet_rb/output").to_s)
    rescue StandardError
      File.expand_path("~/.asrfacet_rb/output")
    end

    def build_rate_controller
      return nil if @options[:adaptive_rate] == false

      ASRFacet::Core::AdaptiveRateController.new(
        base_delay: @options[:delay] || 0,
        max_delay: 5000
      )
    rescue StandardError
      nil
    end

    def build_http_client
      ASRFacet::HTTP::RetryableClient.new(rate_controller: @rate_controller)
    rescue StandardError
      ASRFacet::HTTP::RetryableClient.new
    end

    def build_component(klass, *args)
      instance = instantiate_component(klass, *args)
      ASRFacet::Core::PluginSDK::DependencyInjector.inject(
        instance,
        logger: ASRFacet::Core::ThreadSafe,
        http_client: @http_client,
        event_bus: @bus,
        config: @config
      )
    rescue StandardError
      instantiate_component(klass, *args)
    end

    def instantiate_component(klass, *args)
      params = klass.instance_method(:initialize).parameters
      accepts_client = params.any? { |type, name| %i[key keyreq keyrest].include?(type) && name == :client }
      accepts_options = params.any? { |type, _name| %i[opt rest].include?(type) }

      if accepts_client
        klass.new(*args, client: @http_client)
      elsif accepts_options && !args.empty?
        klass.new(*args)
      else
        klass.new
      end
    rescue StandardError
      klass.new(*args)
    end

    def process_headless_results
      headless_engine = build_component(ASRFacet::Engines::HeadlessEngine, @options)
      return unless headless_engine.respond_to?(:available?) && headless_engine.available?

      Array(@store.all(:http_responses)).each do |entry|
        response = symbolize_keys(entry)
        host = response[:host].to_s
        next if host.empty?
        next if @processed_headless_hosts.include?(host)
        next unless response[:status].to_i == 200 || response[:status_code].to_i == 200

        headless_result = headless_engine.probe("https://#{host}")
        @processed_headless_hosts << host
        next if headless_result.nil?

        @store.add(:headless_results, headless_result.merge(host: host))
        emit(
          :crawl,
          {
            host: host,
            pages_crawled: [],
            links: Array(headless_result[:rendered_links]),
            forms: Array(headless_result[:forms]),
            scripts: [],
            comments: Array(headless_result[:js_errors]),
            interesting_files: [],
            rendered: true
          }
        )
        extract_headless_spa_endpoints(host, headless_result).each do |spa_entry|
          @store.add(:spa_endpoints, spa_entry)
        end
      rescue StandardError => e
        record_failure("headless_engine", "#{host}: #{e.message}")
      end
    rescue StandardError => e
      record_failure("headless_engine", e.message)
    end

    def extract_headless_spa_endpoints(host, headless_result)
      Array(headless_result[:network_requests]).filter_map do |request|
        entry = symbolize_keys(request)
        next if entry[:url].to_s.empty?

        uri = URI.parse(entry[:url].to_s)
        path = uri.path.to_s
        method = entry[:method].to_s.upcase
        next unless path.start_with?("/api/", "/v1/", "/v2/", "/graphql", "/rest/") || %w[POST PUT PATCH DELETE].include?(method)

        {
          url: entry[:url].to_s,
          method: method.empty? ? "GET" : method,
          discovered_from: host
        }
      rescue StandardError
        nil
      end.uniq
    rescue StandardError
      []
    end

    def setup_event_subscribers
      @event_bus.subscribe(:domain) do |data|
        entry = symbolize_keys(data)
        @graph.add_node(entry[:id], type: :domain, data: { ip: entry[:ip] })
      end

      @event_bus.subscribe(:subdomain) do |data|
        entry = symbolize_keys(data)
        host = entry[:host].to_s
        next if host.empty?
        next unless @scope.in_scope?(host)

        @store.add(:subdomains, host)
        @graph.add_node(host, type: :subdomain, data: entry[:data] || {})
        parent = entry[:parent].to_s
        @graph.add_edge(parent, host, relation: :belongs_to) unless parent.empty? || parent == host
        enqueue_subdomain(host)
      end

      @event_bus.subscribe(:dns_record) do |data|
        entry = symbolize_keys(data)
        @store.add(:dns, entry)
        next unless %i[a aaaa].include?(entry[:type].to_sym)
        next unless @scope.in_scope?(entry[:value])

        remember_resolution(entry[:host], entry[:value])
        @store.add(:ips, entry[:value])
        @graph.add_node(entry[:value], type: :ip, data: {})
        @graph.add_edge(entry[:host], entry[:value], relation: :resolves_to)
      end

      @event_bus.subscribe(:open_port) do |data|
        entry = symbolize_keys(data)
        @store.add(:open_ports, entry)
        service_id = "#{entry[:host]}:#{entry[:port]}"
        @graph.add_node(service_id, type: :service, data: entry)
        @graph.add_edge(entry[:host], service_id, relation: :runs_on)
      end

      @event_bus.subscribe(:http_response) do |data|
        entry = symbolize_keys(data)
        @store.add(:http_responses, entry)
        @graph.add_node(entry[:host], type: :subdomain, data: { url: entry[:url], title: entry[:title], technologies: entry[:technologies] })
      end

      @event_bus.subscribe(:ssl_cert) do |data|
        @store.add(:certs, symbolize_keys(data))
      end

      @event_bus.subscribe(:crawl) do |data|
        @store.add(:crawl, symbolize_keys(data))
      end

      @event_bus.subscribe(:js_endpoint) do |data|
        @store.add(:js_endpoints, symbolize_keys(data))
      end

      @event_bus.subscribe(:correlation) do |data|
        @store.add(:correlations, symbolize_keys(data))
      end

      @event_bus.subscribe(:asn) do |data|
        entry = symbolize_keys(data)
        @store.add(:asn, entry)
        asn_id = entry[:asn].to_s.empty? ? "asn:#{entry[:ip]}" : entry[:asn].to_s
        @graph.add_node(asn_id, type: :asn, data: entry)
        @graph.add_edge(entry[:ip], asn_id, relation: :belongs_to)
      end

      @event_bus.subscribe(:finding) do |data|
        entry = symbolize_keys(data)
        @store.add(:findings, entry)
        finding_id = "#{entry[:host]}:#{entry[:title]}"
        @graph.add_node(finding_id, type: :finding, data: entry)
        @graph.add_edge(entry[:host], finding_id, relation: :found_by)
      end

      @event_bus.subscribe(:error) do |data|
        @store.add(:errors, symbolize_keys(data))
      end
    rescue StandardError
      nil
    end

    def symbolize_keys(value)
      case value
      when Hash
        value.each_with_object({}) do |(key, nested), memo|
          memo[key.to_sym] = symbolize_keys(nested)
        end
      when Array
        value.map { |entry| symbolize_keys(entry) }
      else
        value
      end
    rescue StandardError
      {}
    end

    def build_result
      {
        store: @store,
        graph: @graph,
        diff: @diff_result,
        change_summary: @change_summary,
        top_assets: @top_assets,
        js_endpoints: @js_summary,
        correlations: @correlations,
        probabilistic_subdomains: @probabilistic_subdomains,
        stream_path: @streamer&.path,
        output_directory: resolve_output_directory,
        summary: @store.summary
      }
    rescue StandardError
      {
        store: @store,
        graph: @graph,
        diff: {},
        change_summary: "",
        top_assets: [],
        js_endpoints: {},
        correlations: [],
        probabilistic_subdomains: [],
        stream_path: @streamer&.path,
        output_directory: resolve_output_directory,
        summary: {}
      }
    end

    def build_stage_snapshot(index, name)
      summary = @store.summary
      {
        index: index,
        name: name,
        subdomains: summary[:subdomains].to_i,
        ips: summary[:ips].to_i,
        open_ports: summary[:open_ports].to_i,
        http_responses: summary[:http_responses].to_i,
        findings: summary[:findings].to_i,
        errors: summary[:errors].to_i
      }
    rescue StandardError
      { index: index, name: name }
    end
  end
end
