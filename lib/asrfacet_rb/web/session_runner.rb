# Part of ASRFacet-Rb - authorized testing only
require "fileutils"
require "json"
require "time"

module ASRFacet
  module Web
    class SessionRunner
      def initialize(session_store:)
        @session_store = session_store
        @jobs = {}
        @mutex = Mutex.new
      rescue StandardError
        @session_store = session_store
        @jobs = {}
        @mutex = Mutex.new
      end

      def start(session_id)
        return false if running?(session_id)

        thread = Thread.new { run_session(session_id) }
        @mutex.synchronize { @jobs[session_id.to_s] = thread }
        true
      rescue StandardError => e
        @session_store.mark_failed(session_id, e.message)
        false
      end

      def running?(session_id)
        @mutex.synchronize do
          thread = @jobs[session_id.to_s]
          !thread.nil? && thread.alive?
        end
      rescue StandardError
        false
      end

      private

      def run_session(session_id)
        session = @session_store.fetch(session_id)
        raise "Session not found." if session.nil?

        config = symbolize(session[:config] || {})
        target = config[:target].to_s.strip
        raise "A target is required before starting a session." if target.empty?

        @session_store.mark_running(session_id, config: config, target: target)
        result = perform_run(session_id, config, target)
        payload = normalize_payload(result)
        payload[:summary] ||= payload[:store].respond_to?(:summary) ? payload[:store].summary : {}
        payload[:meta] = build_meta(target)
        payload[:artifacts] = save_report_bundle(target, payload)
        @session_store.mark_completed(session_id, payload)
      rescue StandardError => e
        @session_store.mark_failed(session_id, e.message)
      ensure
        @mutex.synchronize { @jobs.delete(session_id.to_s) }
      end

      def perform_run(session_id, config, target)
        mode = config[:mode].to_s
        case mode
        when "passive"
          run_passive(session_id, target, config)
        when "dns"
          run_dns(session_id, target)
        when "ports"
          run_ports(session_id, target, config)
        else
          ASRFacet::Pipeline.new(
            target,
            pipeline_options(config).merge(
              stage_callback: lambda do |index, name, phase = :start, snapshot = {}|
                @session_store.update_stage(session_id, index: index, name: name, phase: phase, snapshot: snapshot)
              end,
              event_callback: lambda do |event_type, data|
                capture_event(session_id, event_type, data)
              end
            )
          ).run
        end
      rescue StandardError
        { store: ASRFacet::ResultStore.new, top_assets: [], summary: {} }
      end

      def run_passive(session_id, target, config)
        store = ASRFacet::ResultStore.new
        @session_store.update_stage(session_id, index: 1, name: "Passive reconnaissance", phase: :start, snapshot: {})
        result = ASRFacet::Passive::Runner.new(target, api_keys(config)).run
        store.add(:subdomains, target)
        Array(result[:subdomains]).each do |subdomain|
          store.add(:subdomains, subdomain)
          capture_event(session_id, :subdomain, { host: subdomain })
        end
        Array(result[:errors]).each { |error| capture_event(session_id, :error, { engine: "passive_runner", reason: error }) }
        @session_store.update_stage(session_id, index: 1, name: "Passive reconnaissance", phase: :complete, snapshot: { subdomains: store.all(:subdomains).size })
        { store: store, top_assets: [], summary: store.summary }
      rescue StandardError
        { store: ASRFacet::ResultStore.new, top_assets: [], summary: {} }
      end

      def run_dns(session_id, target)
        store = ASRFacet::ResultStore.new
        @session_store.update_stage(session_id, index: 1, name: "DNS collection", phase: :start, snapshot: {})
        result = ASRFacet::Engines::DnsEngine.new.run(target)
        result[:data].each do |record_type, values|
          next if %i[wildcard wildcard_ips zone_transfer].include?(record_type)

          Array(values).each do |value|
            entry = { host: target, type: record_type, value: value }
            store.add(:dns, entry)
            capture_event(session_id, :dns_record, entry)
          end
        end
        Array(result[:data][:a]).each { |ip| store.add(:ips, ip) }
        Array(result[:data][:aaaa]).each { |ip| store.add(:ips, ip) }
        @session_store.update_stage(session_id, index: 1, name: "DNS collection", phase: :complete, snapshot: { ips: store.all(:ips).size })
        { store: store, top_assets: [], summary: store.summary }
      rescue StandardError
        { store: ASRFacet::ResultStore.new, top_assets: [], summary: {} }
      end

      def run_ports(session_id, target, config)
        store = ASRFacet::ResultStore.new
        @session_store.update_stage(session_id, index: 1, name: "Port scanning", phase: :start, snapshot: {})
        ASRFacet::Engines::PortEngine.new.scan(target, config[:ports] || "top100", workers: config[:threads]).each do |entry|
          store.add(:open_ports, entry)
          capture_event(session_id, :open_port, entry.merge(host: target))
        end
        @session_store.update_stage(session_id, index: 1, name: "Port scanning", phase: :complete, snapshot: { open_ports: store.all(:open_ports).size })
        { store: store, top_assets: [], summary: store.summary }
      rescue StandardError
        { store: ASRFacet::ResultStore.new, top_assets: [], summary: {} }
      end

      def capture_event(session_id, event_type, data)
        item = symbolize(data)
        message = case event_type.to_sym
                  when :subdomain then "Discovered host #{item[:host]}"
                  when :open_port then "Observed #{item[:host]}:#{item[:port]}/tcp #{item[:service]}".strip
                  when :http_response then "HTTP #{item[:status] || item[:status_code]} #{item[:url] || item[:host]}".strip
                  when :finding then "#{item[:severity].to_s.upcase} #{item[:host]} - #{item[:title]}"
                  when :dns_record then "#{item[:type].to_s.upcase} #{item[:host]} -> #{item[:value]}"
                  when :error then "#{item[:engine]} - #{item[:reason]}"
                  else JSON.generate(item)
                  end
        @session_store.append_event(session_id, type: event_type.to_s, message: message, data: item)
      rescue StandardError
        nil
      end

      def pipeline_options(config)
        {
          ports: config[:ports],
          threads: config[:threads],
          timeout: config[:timeout],
          scope: config[:scope],
          exclude: config[:exclude],
          monitor: config[:monitor],
          top: 10,
          memory: config[:memory],
          headless: config[:headless],
          delay: config[:delay],
          adaptive_rate: config[:adaptive_rate],
          verbose: config[:verbose],
          api_keys: api_keys(config)
        }
      rescue StandardError
        {}
      end

      def api_keys(config)
        { shodan: config[:shodan_key] }
      rescue StandardError
        {}
      end

      def build_meta(target)
        {
          target: target,
          generated_at: Time.now.utc.iso8601,
          output_directory: output_root
        }
      rescue StandardError
        { target: target.to_s, generated_at: Time.now.utc.iso8601, output_directory: output_root }
      end

      def save_report_bundle(target, payload)
        safe_target = safe_name(target)
        stamp = payload.dig(:meta, :generated_at).to_s.gsub(":", "-")
        report_dir = File.join(output_root, "reports", safe_target, stamp)
        FileUtils.mkdir_p(report_dir)
        artifacts = {
          report_directory: report_dir,
          cli_report: File.join(report_dir, "report.cli.txt"),
          txt_report: File.join(report_dir, "report.txt"),
          html_report: File.join(report_dir, "report.html"),
          json_report: File.join(report_dir, "report.json")
        }
        ASRFacet::Output::CliFormatter.new.save(payload, artifacts[:cli_report])
        ASRFacet::Output::TxtFormatter.new.save(payload, artifacts[:txt_report])
        ASRFacet::Output::HtmlFormatter.new.save(payload, artifacts[:html_report])
        ASRFacet::Output::JsonFormatter.new.save(payload, artifacts[:json_report])
        artifacts
      rescue StandardError
        {}
      end

      def output_root
        File.expand_path((ASRFacet::Config.fetch("output", "directory") || "~/.asrfacet_rb/output").to_s)
      rescue StandardError
        File.expand_path("~/.asrfacet_rb/output")
      end

      def normalize_payload(result)
        payload = symbolize(result || {})
        payload[:store] ||= ASRFacet::ResultStore.new
        payload
      rescue StandardError
        { store: ASRFacet::ResultStore.new, top_assets: [], summary: {} }
      end

      def safe_name(value)
        cleaned = value.to_s.downcase.gsub(/[^a-z0-9.\-_]+/, "_")
        cleaned.empty? ? "scan" : cleaned.tr(".", "_")
      rescue StandardError
        "scan"
      end

      def symbolize(value)
        case value
        when Hash
          value.each_with_object({}) do |(key, nested), memo|
            memo[key.to_sym] = symbolize(nested)
          end
        when Array
          value.map { |entry| symbolize(entry) }
        else
          value
        end
      rescue StandardError
        {}
      end
    end
  end
end
