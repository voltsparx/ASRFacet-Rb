# frozen_string_literal: true
# For use only on systems you own or have explicit
# written authorization to test.
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

require "fileutils"
require "json"
require "securerandom"
require "time"

module ASRFacet
  module Web
    class SessionRunner
      def initialize(session_store:)
        @session_store = session_store
        @jobs = {}
        @mutex = Mutex.new
        @runner_id = SecureRandom.hex(6)
      rescue StandardError
        @session_store = session_store
        @jobs = {}
        @mutex = Mutex.new
        @runner_id = "runner"
      end

      def start(session_id)
        return false if running?(session_id)

        thread = Thread.new { run_session(session_id) }
        @mutex.synchronize { @jobs[session_id.to_s] = thread }
        true
      rescue StandardError => e
        @session_store.mark_failed(
          session_id,
          ASRFacet::Core::ErrorReporter.build(
            engine: "session_runner",
            error: e,
            isolated: false,
            context: "Unable to start the requested session"
          )
        )
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

        config = ASRFacet::Web::SessionStore.normalize_config(symbolize(session[:config] || {}))
        target = config[:target].to_s.strip
        raise "A target is required before starting a session." if target.empty?
        integrity = ASRFacet::Core::IntegrityChecker.check(output_root: output_root)
        if ASRFacet::Core::IntegrityChecker.critical?(integrity)
          raise "Framework integrity check failed: #{integrity[:summary]}"
        end

        heartbeat_stop = false
        @session_store.mark_running(session_id, config: config, target: target, process_id: Process.pid, runner_id: @runner_id)
        unless integrity[:status].to_s == "ok"
          @session_store.append_event(session_id, type: "warning", message: integrity[:summary], data: integrity)
        end
        heartbeat_thread = Thread.new do
          Thread.current.report_on_exception = false if Thread.current.respond_to?(:report_on_exception=)
          until heartbeat_stop
            sleep(2)
            @session_store.update_heartbeat(session_id, process_id: Process.pid, runner_id: @runner_id)
          end
        rescue StandardError
          nil
        end
        result = perform_run(session_id, config, target, integrity: integrity)
        payload = normalize_payload(result)
        payload[:summary] ||= payload[:store].respond_to?(:summary) ? payload[:store].summary : {}
        payload[:meta] = build_meta(target)
        payload[:integrity] ||= integrity
        payload[:artifacts] = save_report_bundle(target, payload, requested_format: config[:format])
        Array(payload.dig(:artifacts, :report_errors)).each do |entry|
          @session_store.append_event(
            session_id,
            type: "warning",
            message: "Report render warning for #{entry[:format]}: #{entry[:message]}",
            data: entry
          )
        end
        @session_store.mark_completed(session_id, payload)
      rescue StandardError => e
        @session_store.mark_failed(
          session_id,
          ASRFacet::Core::ErrorReporter.build(
            engine: "session_runner",
            error: e,
            isolated: false,
            context: "The saved session could not finish cleanly"
          )
        )
      ensure
        heartbeat_stop = true if defined?(heartbeat_stop)
        heartbeat_thread&.join(0.2) rescue nil
        heartbeat_thread&.kill rescue nil
        @mutex.synchronize { @jobs.delete(session_id.to_s) }
      end

      def perform_run(session_id, config, target, integrity:)
        mode = config[:mode].to_s
        case mode
        when "passive"
          run_passive(session_id, target, config, integrity: integrity)
        when "dns"
          run_dns(session_id, target, integrity: integrity)
        when "portscan"
          run_portscan(session_id, target, config, integrity: integrity)
        when "ports"
          run_ports(session_id, target, config, integrity: integrity)
        else
          ASRFacet::Pipeline.new(
            target,
            pipeline_options(config).merge(
              integrity_report: integrity,
              stage_callback: lambda do |index, name, phase = :start, snapshot = {}|
                @session_store.update_stage(session_id, index: index, name: name, phase: phase, snapshot: snapshot)
              end,
              event_callback: lambda do |event_type, data|
                capture_event(session_id, event_type, data)
              end
            )
          ).run
        end
      end

      def run_passive(session_id, target, config, integrity:)
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
        {
          store: store,
          top_assets: [],
          summary: store.summary,
          execution: {
            stages: [],
            failures: Array(result[:errors]).map do |error|
              ASRFacet::Core::ErrorReporter.build(engine: "passive_runner", error: error, isolated: true)
            end,
            integrity: integrity
          }
        }
      end

      def run_dns(session_id, target, integrity:)
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
        { store: store, top_assets: [], summary: store.summary, execution: { stages: [], failures: [], integrity: integrity } }
      end

      def run_ports(session_id, target, config, integrity:)
        run_scanner_mode(
          session_id,
          target,
          config.merge(scan_type: "connect", scan_version: false, scan_os: false),
          integrity: integrity,
          stage_name: "Focused port scanning"
        )
      end

      def run_portscan(session_id, target, config, integrity:)
        run_scanner_mode(session_id, target, config, integrity: integrity, stage_name: "Scanner engine")
      end

      def run_scanner_mode(session_id, target, config, integrity:, stage_name:)
        @session_store.update_stage(session_id, index: 1, name: stage_name, phase: :start, snapshot: {})
        scan_result = ASRFacet::Scanner::ScanEngine.new(
          scan_type: config[:scan_type],
          timing: config[:scan_timing],
          verbosity: config[:verbose] ? 1 : 0,
          version_detection: config[:scan_version],
          os_detection: config[:scan_os],
          version_intensity: config[:scan_intensity],
          ports: config[:ports]
        ).scan(target)
        payload = ASRFacet::Scanner::ResultAdapter.to_payload(scan_result, target: target)
        store = payload[:store]
        store.all(:open_ports).each do |entry|
          capture_event(session_id, :open_port, entry.merge(host: entry[:host] || target))
        end
        @session_store.update_stage(
          session_id,
          index: 1,
          name: stage_name,
          phase: :complete,
          snapshot: {
            open_ports: store.all(:open_ports).size,
            filtered_ports: store.all(:filtered_ports).size,
            subdomains: store.all(:subdomains).size,
            ips: store.all(:ips).size
          }
        )
        payload[:execution] = { stages: [], failures: [], integrity: integrity }
        payload
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
          format: config[:format],
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

      def save_report_bundle(target, payload, requested_format:)
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
        artifacts.merge!(render_requested_artifacts(target, payload, report_dir, requested_format))
        artifacts
      rescue StandardError
        {}
      end

      def render_requested_artifacts(target, payload, report_dir, requested_format)
        format = requested_format.to_s.downcase.strip
        return {} if format.empty? || %w[cli txt html json].include?(format)

        artifacts = {}
        router = ASRFacet::Output::OutputRouter.new(
          payload[:store],
          target,
          charts: payload[:charts] || {}
        )
        case format
        when "csv"
          merge_artifact_result!(artifacts, render_csv_artifacts(router, report_dir))
        when "pdf"
          merge_artifact_result!(artifacts, render_single_router_artifact(router, "pdf", File.join(report_dir, "report.pdf"), :pdf_report))
        when "docx"
          merge_artifact_result!(artifacts, render_single_router_artifact(router, "docx", File.join(report_dir, "report.docx"), :docx_report))
        when "sarif"
          merge_artifact_result!(artifacts, render_sarif_artifact(payload, report_dir))
        when "all"
          merge_artifact_result!(artifacts, render_csv_artifacts(router, report_dir))
          merge_artifact_result!(artifacts, render_single_router_artifact(router, "pdf", File.join(report_dir, "report.pdf"), :pdf_report))
          merge_artifact_result!(artifacts, render_single_router_artifact(router, "docx", File.join(report_dir, "report.docx"), :docx_report))
          merge_artifact_result!(artifacts, render_sarif_artifact(payload, report_dir))
        end
        artifacts
      rescue ASRFacet::Error => e
        { report_errors: [{ format: format, message: e.message }] }
      rescue StandardError => e
        { report_errors: [{ format: format, message: e.message }] }
      end

      def merge_artifact_result!(artifacts, result)
        errors = Array(artifacts[:report_errors]) + Array(result.delete(:report_errors))
        artifacts.merge!(result)
        artifacts[:report_errors] = errors unless errors.empty?
        artifacts
      rescue StandardError
        artifacts
      end

      def render_single_router_artifact(router, format, path, artifact_key)
        router.render(format, path)
        { artifact_key => path }
      rescue ASRFacet::Error => e
        { report_errors: [{ format: format, message: e.message }] }
      end

      def render_csv_artifacts(router, report_dir)
        base = File.join(report_dir, "report.csv")
        router.render("csv", base)
        {
          csv_subdomains_report: File.join(report_dir, "report_subdomains.csv"),
          csv_ips_report: File.join(report_dir, "report_ips.csv"),
          csv_ports_report: File.join(report_dir, "report_ports.csv"),
          csv_findings_report: File.join(report_dir, "report_findings.csv"),
          csv_js_endpoints_report: File.join(report_dir, "report_js_endpoints.csv")
        }
      rescue ASRFacet::Error => e
        { report_errors: [{ format: "csv", message: e.message }] }
      end

      def render_sarif_artifact(payload, report_dir)
        path = File.join(report_dir, "report.sarif")
        saved_path = ASRFacet::Output::SarifFormatter.new.save(payload, path)
        raise ASRFacet::Error, "SARIF render failed" if saved_path.to_s.empty? || !File.file?(path)

        { sarif_report: path }
      rescue ASRFacet::Error => e
        { report_errors: [{ format: "sarif", message: e.message }] }
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
