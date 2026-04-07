# Part of ASRFacet-Rb - authorized testing only
require "fileutils"
require "json"
require "time"

module ASRFacet::Output
  class BaseFormatter
    include ASRFacet::Core::PluginSDK

    attr_writer :logger, :http_client, :event_bus, :config

    def self.plugin_type
      :formatter
    rescue StandardError
      :formatter
    end

    def format(_results)
      raise NotImplementedError, "Subclasses must implement #format"
    end

    def save(results, path)
      FileUtils.mkdir_p(File.dirname(path.to_s))
      File.write(path.to_s, format(results))
      path
    rescue StandardError
      nil
    end

    protected

    def payload_for(results)
      if results.is_a?(Hash)
        payload = symbolize_keys(results)
        payload[:store] = normalize_store(payload[:store] || payload)
        payload
      else
        { store: normalize_store(results) }
      end
    rescue StandardError
      { store: {} }
    end

    def normalize_store(store)
      return {} if store.nil?
      return symbolize_keys(store.to_h) if store.respond_to?(:to_h)

      symbolize_keys(store)
    rescue StandardError
      {}
    end

    def primary_target(store)
      data = normalize_store(store)
      Array(data[:subdomains]).first || Array(data[:ips]).first || "target"
    rescue StandardError
      "target"
    end

    def counts_for(store)
      data = normalize_store(store)
      {
        subdomains: Array(data[:subdomains]).size,
        ips: Array(data[:ips]).size,
        open_ports: Array(data[:open_ports]).size,
        http_responses: Array(data[:http_responses]).size,
        findings: Array(data[:findings]).size,
        js_endpoints: Array(data[:js_endpoints]).size + Array(dig_hash(data, :js_endpoints, :endpoints_found)).size,
        spa_endpoints: Array(data[:spa_endpoints]).size,
        correlations: Array(data[:correlations]).size,
        errors: Array(data[:errors]).size
      }
    rescue StandardError
      {}
    end

    def severity_counts(findings)
      counts = Hash.new(0)
      Array(findings).each do |finding|
        counts[finding[:severity].to_sym] += 1
      end
      counts
    rescue StandardError
      {}
    end

    def summary_narrative(payload)
      data = normalize_store(payload[:store])
      counts = counts_for(data)
      findings = Array(data[:findings])

      lines = []
      lines << "The run mapped #{counts[:subdomains]} subdomains and #{counts[:ips]} resolved IPs from the authorized scope."
      lines << "It confirmed #{counts[:open_ports]} exposed services and #{counts[:http_responses]} web responses that deserve review."
      if findings.empty?
        lines << "No heuristic findings were generated, which usually means the built-in checks did not spot obvious weak signals."
      else
        ordered = severity_counts(findings)
        lines << "Finding generation produced #{findings.size} issues, including #{ordered[:critical]} critical and #{ordered[:high]} high-severity entries."
      end
      if payload[:diff].to_h.empty?
        lines << "No historical delta was recorded for this run."
      else
        lines << "A historical change summary is available, which helps separate new exposure from older baseline inventory."
      end
      lines
    rescue StandardError
      []
    end

    def recommendations_for(payload)
      data = normalize_store(payload[:store])
      findings = Array(data[:findings])
      recommendations = []

      if findings.any? { |finding| %i[critical high].include?(finding[:severity].to_sym) }
        recommendations << "Triage critical and high-severity findings first because they are the fastest route to meaningful security validation."
      end

      if Array(data[:spa_endpoints]).any? || Array(dig_hash(payload, :js_endpoints, :endpoints_found)).any?
        recommendations << "Review discovered API and JavaScript endpoints for hidden routes, missing authorization, and forgotten administrative functions."
      end

      if payload[:diff].to_h.any?
        recommendations << "Compare the change summary against the previous baseline so new assets are validated before they become blind spots."
      end

      if Array(data[:open_ports]).any? { |entry| [22, 3389, 5900, 2375, 6443].include?(entry[:port].to_i) }
        recommendations << "Inspect exposed management and remote-access services carefully because they often provide the highest-value follow-up paths."
      end

      recommendations << "Use the HTML report for the richest offline review and keep the JSON output for automation or downstream tooling." if recommendations.empty?
      recommendations
    rescue StandardError
      []
    end

    def meaning_for(section_name)
      meanings = {
        "subdomains" => "These are the hosts the tool believes belong to the authorized target surface.",
        "open_ports" => "These are reachable TCP services that expand the external exposure of the target.",
        "http_responses" => "These responses show which hosts are serving web content and which technologies appear exposed.",
        "findings" => "These are heuristic observations that may deserve manual validation and deeper testing.",
        "js_endpoints" => "These endpoints came from JavaScript parsing and often reveal hidden API routes or client-side behavior.",
        "spa_endpoints" => "These endpoints were observed from rendered application traffic and often expose deeper client-side API use.",
        "correlations" => "These entries connect related assets so you can pivot more efficiently during manual review.",
        "dns" => "These DNS records explain how names resolve and which systems support the visible surface."
      }
      meanings.fetch(section_name.to_s, "This section contains additional reconnaissance context collected during the run.")
    rescue StandardError
      ""
    end

    def artifact_rows(payload)
      artifacts = symbolize_keys(payload[:artifacts] || {})
      artifacts.filter_map do |key, value|
        next if value.to_s.empty?

        [key.to_s.tr("_", " "), value]
      end
    rescue StandardError
      []
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

    def dig_hash(value, *keys)
      keys.reduce(value) do |memo, key|
        break nil unless memo.is_a?(Hash)

        memo[key]
      end
    rescue StandardError
      nil
    end
  end
end
